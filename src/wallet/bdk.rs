//! The Wallet API.
//!
//! Currently, wallet synchronization is exclusively performed through RPC for makers.
//! In the future, takers might adopt alternative synchronization methods, such as lightweight wallet solutions.

use bdk_chain::{
    bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
        blockdata::constants::genesis_block,
        ecdsa::Signature,
        hashes::{
            hash160::Hash as Hash160,
            hex::FromHex,
            sha256d::{self, Hash as doublesha},
            Hash,
        },
        opcodes,
        script::{Builder, Instruction},
        secp256k1::{
            self,
            rand::{rngs::OsRng, RngCore},
            All, Keypair, Message, Secp256k1, SecretKey,
        },
        sighash::{EcdsaSighashType, SighashCache},
        transaction::Version,
        Address, Amount, Network, OutPoint, PublicKey, Script, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    },
    keychain::KeychainTxOutIndex,
    local_chain::LocalChain,
    miniscript::{
        descriptor::{DescriptorXKey, KeyMap, Wildcard},
        DescriptorPublicKey, ForEachKey,
    },
    ConfirmationTimeHeightAnchor, IndexedTxGraph,
};

use bdk_persist::Persist;
use bdk_wallet::{
    descriptor::{Descriptor, DescriptorError, ExtendedDescriptor, IntoWalletDescriptor},
    signer::{SignerOrdering, SignersContainer, TransactionSigner},
};

use std::fmt::Debug;

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs::OpenOptions,
    io::{BufReader, BufWriter},
    iter,
    num::ParseIntError,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bdk_wallet::descriptor::calc_checksum;

use crate::protocol::error::ContractError;
use bitcoind::{
    anyhow,
    bitcoincore_rpc::{
        bitcoincore_rpc_json::ListUnspentResultEntry, json::CreateRawTransactionInput, Auth,
        Client, RawTx, RpcApi,
    },
};

use crate::{
    protocol::{
        contract::{
            self, apply_two_signatures_to_2of2_multisig_spend, create_multisig_redeemscript,
            read_contract_locktime, read_hashlock_pubkey_from_contract,
            read_hashvalue_from_contract, read_pubkeys_from_multisig_redeemscript,
            read_timelock_pubkey_from_contract, sign_contract_tx, verify_contract_tx_sig,
        },
        messages::Preimage,
    },
    utill::{generate_keypair, get_hd_path_from_descriptor, redeemscript_to_scriptpubkey},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use bip39::Mnemonic;

use bdk_wallet::wallet::{LoadError, NewError};

// these subroutines are coded so that as much as possible they keep all their
// data in the bitcoin core wallet
// for example which privkey corresponds to a scriptpubkey is stored in hd paths

const HARDENDED_DERIVATION: &str = "m/84'/1'/0'";

pub struct Wallet {
    signers: HashMap<KeychainKind, Arc<SignersContainer>>,
    chain: LocalChain,
    indexed_graph: IndexedTxGraph<ConfirmationTimeHeightAnchor, KeychainTxOutIndex<KeychainKind>>,
    persist: Persist<ChangeSet>,
    store: WalletStore,
    network: Network,
    secp: Secp256k1<All>,
    rpc: Client,
}

/// Speicfy the keychain derivation path from [`HARDENDED_DERIVATION`]
/// Each kind represents an unhardened index value. Starting with External = 0.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum KeychainKind {
    External,
    Internal,
    Fidelity,
    SwapCoin,
    Contract,
}

impl KeychainKind {
    fn index_num(&self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
            Self::Fidelity => 2,
            Self::SwapCoin => 3,
            Self::Contract => 4,
        }
    }

    pub fn iterator() -> std::slice::Iter<'static, KeychainKind> {
        static KINDS: [KeychainKind; 5] = [
            KeychainKind::External,
            KeychainKind::Internal,
            KeychainKind::Fidelity,
            KeychainKind::SwapCoin,
            KeychainKind::Contract,
        ];

        KINDS.iter()
    }
}

const WATCH_ONLY_SWAPCOIN_LABEL: &str = "watchonly_swapcoin_label";

/// The changes made to a wallet by applying an [`Update`].
pub type ChangeSet = bdk_persist::CombinedChangeSet<KeychainKind, ConfirmationTimeHeightAnchor>;

/// Enum representing additional data needed to spend a UTXO, in addition to `ListUnspentResultEntry`.
// data needed to find information  in addition to ListUnspentResultEntry
// about a UTXO required to spend it
#[derive(Debug, Clone)]
pub enum UTXOSpendInfo {
    SeedCoin {
        path: String,
        input_value: u64,
    },
    SwapCoin {
        multisig_redeemscript: ScriptBuf,
    },
    TimelockContract {
        swapcoin_multisig_redeemscript: ScriptBuf,
        input_value: u64,
    },
    HashlockContract {
        swapcoin_multisig_redeemscript: ScriptBuf,
        input_value: u64,
    },
    FidelityBondCoin {
        index: u32,
        input_value: u64,
    },
}

// Custom type to handle complex return values.
type SwapCoinsInfo<'a> = (
    Vec<(&'a IncomingSwapCoin, ListUnspentResultEntry)>,
    Vec<(&'a OutgoingSwapCoin, ListUnspentResultEntry)>,
);

impl Wallet {
    pub fn init(
        path: &PathBuf,
        seedphrase: String,
        passphrase: String,
        rpc_config: &RPCConfig,
        wallet_birthday: Option<u64>,
        network: Network,
    ) -> Result<Self, NewError> {
        let file_name = path
            .file_name()
            .expect("file name expected")
            .to_str()
            .expect("expected")
            .to_string();
        let store = WalletStore::init(
            file_name,
            path,
            network,
            seedphrase.clone(),
            passphrase.clone(),
            wallet_birthday,
        )
        .expect("failed to initialise the walletstore");

        let genesis_hash = genesis_block(network).block_hash();

        let secp = Secp256k1::new();
        let (chain, chain_changeset) = LocalChain::from_genesis_hash(genesis_hash);
        let mut index = KeychainTxOutIndex::<KeychainKind>::default();

        // create descriptors for each kind from seedpharse & passphrase
        // containig Xpriv

        let indexed_graph = IndexedTxGraph::new(index.clone());

        let mut persist = Persist::new(());
        persist.stage(ChangeSet {
            chain: chain_changeset,
            indexed_tx_graph: indexed_graph.initial_changeset(),
            network: Some(network),
        });
        persist.commit().map_err(NewError::Persist)?;

        let rpc = Client::try_from(rpc_config).expect("Failed to load Client from rpc config");

        let mut wallet = Wallet {
            signers: HashMap::default(),
            chain,
            indexed_graph,
            persist,
            store,
            network,
            secp: secp.clone(),
            rpc,
        };

        let kind_descriptor_map = wallet
            .create_wallet_descriptors()
            .expect("failed to create descriptors");

        let kind_descriptor_map_ref: HashMap<_, _> = kind_descriptor_map
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();
        let signer_map =
            Wallet::create_signers(&mut index, &secp, kind_descriptor_map_ref, network)
                .map_err(NewError::Descriptor)?;

        wallet.signers = signer_map;

        Ok(wallet)
    }

    fn load_from_changeset(
        store: WalletStore,
        changeset: ChangeSet,
        rpc_config: &RPCConfig,
    ) -> Result<Self, LoadError> {
        let secp = Secp256k1::new();
        let network = changeset.network.ok_or(LoadError::MissingNetwork)?;
        let chain =
            LocalChain::from_changeset(changeset.chain).map_err(|_| LoadError::MissingGenesis)?;
        let mut index = KeychainTxOutIndex::<KeychainKind>::default();

        let kind_descriptor_map: HashMap<KeychainKind, Descriptor<DescriptorPublicKey>> = changeset
            .indexed_tx_graph
            .indexer
            .keychains_added
            .clone()
            .into_iter()
            .map(|(kind, descriptor)| (kind, descriptor))
            .collect();

        // create the signer mapping
        let signers = Wallet::create_signers(&mut index, &secp, kind_descriptor_map, network)
            .expect("Can't fail: we passed in valid descriptors, recovered from the changeset");

        let mut indexed_graph = IndexedTxGraph::new(index);
        indexed_graph.apply_changeset(changeset.indexed_tx_graph);

        let persist = Persist::new(());

        // load rpc
        let rpc = Client::try_from(rpc_config)
            .expect("Wallet name of database file and core missmatch, expected {}, found {}");

        Ok(Wallet {
            signers,
            chain,
            indexed_graph,
            persist,
            store,
            network,
            secp,
            rpc,
        })
    }

    /// Load [`Wallet`] from the given persistence backend
    /// It also adds the private keys of the passed-in descriptors to the [`Wallet`].
    ///
    /// Note
    ///
    /// This function adds private keys from each kind of descriptor, except Swapcoin.
    /// The Swapcoin descriptor "wsh(sorted_multi(Xpub1, Xpub2))" contains no private keys.

    pub fn load<E>(
        path: &PathBuf,
        rpc_config: &RPCConfig,
        network: Network,
    ) -> Result<Self, LoadError> {
        let store =
            WalletStore::read_from_disk(path).expect("failed to read walletstore from given path");

        let changeset = store
            .load_from_persistence()
            .map_err(LoadError::Persist)?
            .ok_or(LoadError::NotInitialized)?;

        let wallet = Self::load_from_changeset(store, changeset, rpc_config)?;

        // get descriptors containing Xpriv in order to add
        // add signers manually
        let kind_descriptor_map = wallet
            .create_wallet_descriptors()
            .expect("failed to create descriptors");

        for (keychain, descriptor) in kind_descriptor_map {
            let (descriptor, keymap) = descriptor
                .into_wallet_descriptor(&wallet.secp, network)
                .map_err(|err| LoadError::Descriptor(err))?;

            if !keymap.is_empty() {
                let signer_container = SignersContainer::build(keymap, &descriptor, &wallet.secp);

                signer_container.signers().into_iter().for_each(|signer| {
                    wallet.add_signer(keychain, SignerOrdering::default(), *signer)
                })
            }
        }

        Ok(wallet)
    }

    /// Update external index and saves to disk.
    pub fn update_external_index(&mut self, new_external_index: u32) -> Result<(), WalletError> {
        self.store.external_index = new_external_index;
        self.save_to_disk()
    }

    /// Update the existing file. Error if path does not exist.
    pub fn save_to_disk(&self) -> Result<(), WalletError> {
        self.store.write_to_disk(&self.wallet_file_path)
    }

    /// Finds an incoming swap coin with the specified multisig redeem script.
    pub fn find_incoming_swapcoin(
        &self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Option<&IncomingSwapCoin> {
        self.store.incoming_swapcoins.get(multisig_redeemscript)
    }

    /// Finds an outgoing swap coin with the specified multisig redeem script.
    pub fn find_outgoing_swapcoin(
        &self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Option<&OutgoingSwapCoin> {
        self.store.outgoing_swapcoins.get(multisig_redeemscript)
    }

    /// Finds a mutable reference to an incoming swap coin with the specified multisig redeem script.
    pub fn find_incoming_swapcoin_mut(
        &mut self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Option<&mut IncomingSwapCoin> {
        self.store.incoming_swapcoins.get_mut(multisig_redeemscript)
    }

    /// Adds an incoming swap coin to the wallet.
    pub fn add_incoming_swapcoin(&mut self, coin: &IncomingSwapCoin) {
        self.store
            .incoming_swapcoins
            .insert(coin.get_multisig_redeemscript(), coin.clone());
    }

    /// Adds an outgoing swap coin to the wallet.
    pub fn add_outgoing_swapcoin(&mut self, coin: &OutgoingSwapCoin) {
        self.store
            .outgoing_swapcoins
            .insert(coin.get_multisig_redeemscript(), coin.clone());
    }

    /// Removes an incoming swap coin with the specified multisig redeem script from the wallet.
    pub fn remove_incoming_swapcoin(
        &mut self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Result<Option<IncomingSwapCoin>, WalletError> {
        Ok(self.store.incoming_swapcoins.remove(multisig_redeemscript))
    }

    /// Removes an outgoing swap coin with the specified multisig redeem script from the wallet.
    pub fn remove_outgoing_swapcoin(
        &mut self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Result<Option<OutgoingSwapCoin>, WalletError> {
        Ok(self.store.outgoing_swapcoins.remove(multisig_redeemscript))
    }

    /// Gets a reference to the list of incoming swap coins in the wallet.
    pub fn get_incoming_swapcoin_list(
        &self,
    ) -> Result<&HashMap<ScriptBuf, IncomingSwapCoin>, WalletError> {
        Ok(&self.store.incoming_swapcoins)
    }

    /// Gets a reference to the list of outgoing swap coins in the wallet.
    pub fn get_outgoing_swapcoin_list(
        &self,
    ) -> Result<&HashMap<ScriptBuf, OutgoingSwapCoin>, WalletError> {
        Ok(&self.store.outgoing_swapcoins)
    }

    /// Gets the total count of swap coins in the wallet.
    pub fn get_swapcoins_count(&self) -> usize {
        self.store.incoming_swapcoins.len() + self.store.outgoing_swapcoins.len()
    }

    /// Calculates the total balance of the wallet, including swap coins, live contracts and fidelity bonds.
    pub fn balance(&self) -> Result<Amount, WalletError> {
        Ok(self
            .list_all_utxo_spend_info(None)?
            .iter()
            .fold(Amount::ZERO, |a, (utxo, _)| a + utxo.amount))
    }

    /// Calculates the fidelity balance of the wallet.
    /// Optionally takes in a list of UTXOs to reduce rpc call. If None is provided, the full list is fetched from core rpc.
    pub fn balance_fidelity_bonds(
        &self,
        utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Amount, WalletError> {
        Ok(self
            .list_fidelity_spend_info(utxos)?
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount))
    }

    /// Calculates live contract balance of the wallet.
    /// Optionally takes in a list of UTXOs to reduce rpc call. If None is provided, the full list is fetched from core rpc.
    pub fn balance_live_contract(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Amount, WalletError> {
        Ok(self
            .list_live_contract_spend_info(all_utxos)?
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount))
    }

    /// Calculates the descriptor utxo balance of the wallet.
    /// Optionally takes in a list of UTXOs to reduce rpc call. If None is provided, the full list is fetched from core rpc.
    pub fn balance_descriptor_utxo(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Amount, WalletError> {
        Ok(self
            .list_descriptor_utxo_spend_info(all_utxos)?
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount))
    }

    /// Calculates the swap coin balance of the wallet.
    /// Optionally takes in a list of UTXOs to reduce rpc call. If None is provided, the full list is fetched from core rpc.
    pub fn balance_swap_coins(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Amount, WalletError> {
        Ok(self
            .list_swap_coin_utxo_spend_info(all_utxos)?
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount))
    }

    /// Checks if the previous output (prevout) matches the cached contract in the wallet.
    ///
    /// This function is used in two scenarios:
    /// 1. When the maker has received the message `signsendercontracttx`.
    /// 2. When the maker receives the message `proofoffunding`.
    ///
    /// ## Cases when receiving `signsendercontracttx`:
    /// - Case 1: Previous output in cache doesn't have any contract => Ok
    /// - Case 2: Previous output has a contract, and it matches the given contract => Ok
    /// - Case 3: Previous output has a contract, but it doesn't match the given contract => Reject
    ///
    /// ## Cases when receiving `proofoffunding`:
    /// - Case 1: Previous output doesn't have an entry => Weird, how did they get a signature?
    /// - Case 2: Previous output has an entry that matches the contract => Ok
    /// - Case 3: Previous output has an entry that doesn't match the contract => Reject
    ///
    /// The two cases are mostly the same, except for Case 1 in `proofoffunding`, which shouldn't happen.
    pub fn does_prevout_match_cached_contract(
        &self,
        prevout: &OutPoint,
        contract_scriptpubkey: &Script,
    ) -> Result<bool, WalletError> {
        //let wallet_file_data = Wallet::load_wallet_file_data(&self.wallet_file_path[..])?;
        Ok(match self.store.prevout_to_contract_map.get(prevout) {
            Some(c) => c == contract_scriptpubkey,
            None => true,
        })
    }

    /// Dynamic address import count function. 10 for tests, 5000 for production.
    pub fn get_addrss_import_count(&self) -> u32 {
        if cfg!(feature = "integration-test") {
            10
        } else {
            5000
        }
    }

    /// Stores an entry into [`WalletStore`]'s prevout-to-contract map.
    /// If the prevout already existed with a contract script, this will update the existing contract.
    pub fn cache_prevout_to_contract(
        &mut self,
        prevout: OutPoint,
        contract: ScriptBuf,
    ) -> Result<(), WalletError> {
        if let Some(contract) = self.store.prevout_to_contract_map.insert(prevout, contract) {
            log::warn!(
                "Prevout to Contract map updated.\nExisting Contract: {}",
                contract
            );
        }
        Ok(())
    }

    //pub fn get_recovery_phrase_from_file()

    /// Wallet descriptors are derivable. Currently only supports two KeychainKind. Internal and External.
    fn get_wallet_descriptors(&self) -> Result<HashMap<KeychainKind, String>, WalletError> {
        let secp = Secp256k1::new();
        let wallet_xpub = Xpub::from_priv(
            &secp,
            &self
                .store
                .master_key
                .derive_priv(
                    &secp,
                    &DerivationPath::from_str(HARDENDED_DERIVATION).unwrap(),
                )
                .unwrap(),
        );

        // Get descriptors for external and internal keychain. Other chains are not supported yet.
        let x = [KeychainKind::External, KeychainKind::Internal]
            .iter()
            .map(|keychain| {
                let descriptor_without_checksum =
                    format!("wpkh({}/{}/*)", wallet_xpub, keychain.index_num());
                let decriptor = format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    calc_checksum(&descriptor_without_checksum).unwrap()
                );
                (*keychain, decriptor)
            })
            .collect::<HashMap<KeychainKind, String>>();

        Ok(x)
        //descriptors.map_err(|e| TeleportError::Rpc(e))
    }

    /// Checks if the addresses derived from the wallet descriptor is imported upto full index range.
    /// Returns the list of descriptors not imported yet
    /// Index range depend on [`WalletMode`].
    /// Normal => 5000
    /// Test => 6
    pub(super) fn get_unimported_wallet_desc(&self) -> Result<Vec<String>, WalletError> {
        let mut unimported = Vec::new();
        for (_, descriptor) in self.get_wallet_descriptors()? {
            let first_addr = self.rpc.derive_addresses(&descriptor, Some([0, 0]))?[0].clone();

            let last_index = self.get_addrss_import_count() - 1;
            let last_addr = self
                .rpc
                .derive_addresses(&descriptor, Some([last_index, last_index]))?[0]
                .clone();

            let first_addr_imported = self
                .rpc
                .get_address_info(&first_addr.assume_checked())?
                .is_watchonly
                .unwrap_or(false);
            let last_addr_imported = self
                .rpc
                .get_address_info(&last_addr.assume_checked())?
                .is_watchonly
                .unwrap_or(false);

            if !first_addr_imported || !last_addr_imported {
                unimported.push(descriptor);
            }
        }

        Ok(unimported)
    }

    /// Gets the external index from the wallet.
    pub fn get_external_index(&self) -> &u32 {
        &self.store.external_index
    }

    /// Core wallet label is the master XPub fingerint.
    pub fn get_core_wallet_label(&self) -> String {
        let secp = Secp256k1::new();
        let m_xpub = Xpub::from_priv(&secp, &self.store.master_key);
        m_xpub.fingerprint().to_string()
    }

    fn create_contract_scriptpubkey_outgoing_swapcoin_hashmap(
        &self,
    ) -> HashMap<ScriptBuf, &OutgoingSwapCoin> {
        self.store
            .outgoing_swapcoins
            .values()
            .map(|osc| {
                (
                    redeemscript_to_scriptpubkey(&osc.contract_redeemscript),
                    osc,
                )
            })
            .collect::<HashMap<_, _>>()
    }

    fn create_contract_scriptpubkey_incoming_swapcoin_hashmap(
        &self,
    ) -> HashMap<ScriptBuf, &IncomingSwapCoin> {
        self.store
            .incoming_swapcoins
            .values()
            .map(|isc| {
                (
                    redeemscript_to_scriptpubkey(&isc.contract_redeemscript),
                    isc,
                )
            })
            .collect::<HashMap<_, _>>()
    }

    /// Locks the fidelity and live_contract utxos which are not considered for spending from the wallet.
    pub fn lock_unspendable_utxos(&self) -> Result<(), WalletError> {
        self.rpc.unlock_unspent_all()?;

        let all_unspents = self
            .rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?;
        let utxos_to_lock = &all_unspents
            .into_iter()
            .filter(|u| self.check_descriptor_utxo_or_swap_coin(u).is_none())
            .map(|u| OutPoint {
                txid: u.txid,
                vout: u.vout,
            })
            .collect::<Vec<OutPoint>>();
        self.rpc.lock_unspent(utxos_to_lock)?;
        Ok(())
    }

    /// Checks if a UTXO belongs to fidelity bonds, and then returns corresponding UTXOSpendInfo
    fn check_if_fidelity(&self, utxo: &ListUnspentResultEntry) -> Option<UTXOSpendInfo> {
        self.store
            .fidelity_bond
            .iter()
            .find_map(|(i, (bond, _, _))| {
                if bond.script_pub_key() == utxo.script_pub_key
                    && bond.amount == utxo.amount.to_sat()
                {
                    Some(UTXOSpendInfo::FidelityBondCoin {
                        index: *i,
                        input_value: bond.amount,
                    })
                } else {
                    None
                }
            })
    }

    /// Checks if a UTXO belongs to live contracts, and then returns corresponding UTXOSpendInfo
    fn check_if_live_contract(&self, utxo: &ListUnspentResultEntry) -> Option<UTXOSpendInfo> {
        let (contract_scriptpubkeys_outgoing, contract_scriptpubkeys_incoming) = (
            self.create_contract_scriptpubkey_outgoing_swapcoin_hashmap(),
            self.create_contract_scriptpubkey_incoming_swapcoin_hashmap(),
        );

        if let Some(outgoing_swapcoin) = contract_scriptpubkeys_outgoing.get(&utxo.script_pub_key) {
            if utxo.confirmations >= outgoing_swapcoin.get_timelock().into() {
                return Some(UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                    input_value: utxo.amount.to_sat(),
                });
            }
        } else if let Some(incoming_swapcoin) =
            contract_scriptpubkeys_incoming.get(&utxo.script_pub_key)
        {
            if incoming_swapcoin.is_hash_preimage_known() && utxo.confirmations >= 1 {
                return Some(UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript: incoming_swapcoin.get_multisig_redeemscript(),
                    input_value: utxo.amount.to_sat(),
                });
            }
        }
        None
    }

    /// Checks if a UTXO belongs to descriptor or swap coin, and then returns corresponding UTXOSpendInfo
    fn check_descriptor_utxo_or_swap_coin(
        &self,
        utxo: &ListUnspentResultEntry,
    ) -> Option<UTXOSpendInfo> {
        if let Some(descriptor) = &utxo.descriptor {
            // Descriptor logic here
            if let Some(ret) = get_hd_path_from_descriptor(descriptor) {
                //utxo is in a hd wallet
                let (fingerprint, addr_type, index) = ret;

                let secp = Secp256k1::new();
                let master_private_key = self
                    .store
                    .master_key
                    .derive_priv(
                        &secp,
                        &DerivationPath::from_str(HARDENDED_DERIVATION).unwrap(),
                    )
                    .unwrap();
                if fingerprint == master_private_key.fingerprint(&secp).to_string() {
                    return Some(UTXOSpendInfo::SeedCoin {
                        path: format!("m/{}/{}", addr_type, index),
                        input_value: utxo.amount.to_sat(),
                    });
                }
            } else {
                //utxo might be one of our swapcoins
                let found = self
                    .find_incoming_swapcoin(
                        utxo.witness_script
                            .as_ref()
                            .unwrap_or(&ScriptBuf::from(Vec::from_hex("").unwrap())),
                    )
                    .map_or(false, |sc| sc.other_privkey.is_some())
                    || self
                        .find_outgoing_swapcoin(
                            utxo.witness_script
                                .as_ref()
                                .unwrap_or(&ScriptBuf::from(Vec::from_hex("").unwrap())),
                        )
                        .map_or(false, |sc| sc.hash_preimage.is_some());
                if found {
                    return Some(UTXOSpendInfo::SwapCoin {
                        multisig_redeemscript: utxo.witness_script.as_ref().unwrap().clone(),
                    });
                }
            };
        }
        None
    }

    /// Returns a list of all UTXOs tracked by the wallet. Including fidelity, live_contracts and swap coins.
    pub fn get_all_utxo(&self) -> Result<Vec<ListUnspentResultEntry>, WalletError> {
        self.rpc.unlock_unspent_all()?;
        let all_utxos = self
            .rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?;
        Ok(all_utxos)
    }

    pub fn get_all_locked_utxo(&self) -> Result<Vec<ListUnspentResultEntry>, WalletError> {
        let all_utxos = self
            .rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?;
        Ok(all_utxos)
    }
    /// Returns a list all utxos with their spend info tracked by the wallet.
    /// Optionally takes in an Utxo list to reduce RPC calls. If None is given, the
    /// full list of utxo is fetched from core rpc.
    pub fn list_all_utxo_spend_info(
        &self,
        utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let owned_utxo: Option<Vec<ListUnspentResultEntry>> = if utxos.is_none() {
            Some(self.get_all_utxo()?)
        } else {
            None
        };

        let all_utxos = utxos.unwrap_or_else(|| owned_utxo.as_ref().unwrap());

        let processed_utxos = all_utxos
            .iter()
            .filter_map(|utxo| {
                let mut spend_info = self.check_if_fidelity(utxo);
                if spend_info.is_none() {
                    spend_info = self.check_if_live_contract(utxo);
                }
                if spend_info.is_none() {
                    spend_info = self.check_descriptor_utxo_or_swap_coin(utxo);
                }
                spend_info.map(|info| (utxo.clone(), info))
            })
            .collect::<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>>();

        Ok(processed_utxos)
    }

    /// Lists live contract UTXOs along with their [UTXOSpendInfo].
    pub fn list_live_contract_spend_info(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let all_valid_utxo = self.list_all_utxo_spend_info(all_utxos)?;
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| {
                matches!(x.1, UTXOSpendInfo::HashlockContract { .. })
                    || matches!(x.1, UTXOSpendInfo::TimelockContract { .. })
            })
            .cloned()
            .collect();
        Ok(filtered_utxos)
    }

    /// Lists fidelity UTXOs along with their [UTXOSpendInfo].
    pub fn list_fidelity_spend_info(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let all_valid_utxo = self.list_all_utxo_spend_info(all_utxos)?;
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::FidelityBondCoin { .. }))
            .cloned()
            .collect();
        Ok(filtered_utxos)
    }

    /// Lists descriptor UTXOs along with their [UTXOSpendInfo].
    pub fn list_descriptor_utxo_spend_info(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let all_valid_utxo = self.list_all_utxo_spend_info(all_utxos)?;
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::SeedCoin { .. }))
            .cloned()
            .collect();
        Ok(filtered_utxos)
    }

    /// Lists swap coin UTXOs along with their [UTXOSpendInfo].
    pub fn list_swap_coin_utxo_spend_info(
        &self,
        all_utxos: Option<&Vec<ListUnspentResultEntry>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let all_valid_utxo = self.list_all_utxo_spend_info(all_utxos)?;
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::SwapCoin { .. }))
            .cloned()
            .collect();
        Ok(filtered_utxos)
    }

    /// Finds incomplete coin swaps in the wallet.
    pub fn find_incomplete_coinswaps(
        &self,
    ) -> Result<HashMap<Hash160, SwapCoinsInfo>, WalletError> {
        self.rpc.unlock_unspent_all()?;

        let completed_coinswap_hashvalues = self
            .store
            .incoming_swapcoins
            .values()
            .filter(|sc| sc.other_privkey.is_some())
            .map(|sc| sc.get_hashvalue())
            .collect::<HashSet<Hash160>>();

        let mut incomplete_swapcoin_groups = HashMap::<Hash160, SwapCoinsInfo>::new();
        let get_hashvalue = |s: &dyn SwapCoin| {
            let swapcoin_hashvalue = s.get_hashvalue();
            if completed_coinswap_hashvalues.contains(&swapcoin_hashvalue) {
                return None;
            }
            Some(swapcoin_hashvalue)
        };
        for utxo in self
            .rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?
        {
            if utxo.descriptor.is_none() {
                continue;
            }
            let multisig_redeemscript = if let Some(rs) = utxo.witness_script.as_ref() {
                rs
            } else {
                continue;
            };
            if let Some(s) = self.find_incoming_swapcoin(multisig_redeemscript) {
                if let Some(swapcoin_hashvalue) = get_hashvalue(s) {
                    incomplete_swapcoin_groups
                        .entry(swapcoin_hashvalue)
                        .or_insert((
                            Vec::<(&IncomingSwapCoin, ListUnspentResultEntry)>::new(),
                            Vec::<(&OutgoingSwapCoin, ListUnspentResultEntry)>::new(),
                        ))
                        .0
                        .push((s, utxo));
                }
            } else if let Some(s) = self.find_outgoing_swapcoin(multisig_redeemscript) {
                if let Some(swapcoin_hashvalue) = get_hashvalue(s) {
                    incomplete_swapcoin_groups
                        .entry(swapcoin_hashvalue)
                        .or_insert((
                            Vec::<(&IncomingSwapCoin, ListUnspentResultEntry)>::new(),
                            Vec::<(&OutgoingSwapCoin, ListUnspentResultEntry)>::new(),
                        ))
                        .1
                        .push((s, utxo));
                }
            } else {
                continue;
            };
        }
        Ok(incomplete_swapcoin_groups)
    }

    /// A simplification of `find_incomplete_coinswaps` function
    pub fn find_unfinished_swapcoins(&self) -> (Vec<IncomingSwapCoin>, Vec<OutgoingSwapCoin>) {
        let unfinished_incomins = self
            .store
            .incoming_swapcoins
            .iter()
            .filter_map(|(_, ic)| {
                if ic.other_privkey.is_none() {
                    Some(ic.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let unfinished_outgoings = self
            .store
            .outgoing_swapcoins
            .iter()
            .filter_map(|(_, oc)| {
                if oc.hash_preimage.is_none() {
                    Some(oc.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        (unfinished_incomins, unfinished_outgoings)
    }

    /// Finds live contract unspent outputs in the wallet.
    // live contract refers to a contract tx which has been broadcast
    // i.e. where there are UTXOs protected by contract_redeemscript's that we know about
    pub fn find_live_contract_unspents(&self) -> Result<SwapCoinsInfo, WalletError> {
        // populate hashmaps where key is contract scriptpubkey and value is the swapcoin
        let contract_scriptpubkeys_incoming_swapcoins =
            self.create_contract_scriptpubkey_incoming_swapcoin_hashmap();
        let contract_scriptpubkeys_outgoing_swapcoins =
            self.create_contract_scriptpubkey_outgoing_swapcoin_hashmap();

        self.rpc.unlock_unspent_all()?;
        let listunspent = self
            .rpc
            .list_unspent(Some(0), Some(9999999), None, None, None)?;

        let (incoming_swapcoins_utxos, outgoing_swapcoins_utxos): (Vec<_>, Vec<_>) = listunspent
            .iter()
            .map(|u| {
                (
                    contract_scriptpubkeys_incoming_swapcoins.get(&u.script_pub_key),
                    contract_scriptpubkeys_outgoing_swapcoins.get(&u.script_pub_key),
                    u,
                )
            })
            .filter(|isc_osc_u| (isc_osc_u.0.is_some() || isc_osc_u.1.is_some()))
            .partition(|isc_osc_u| isc_osc_u.0.is_some());

        Ok((
            incoming_swapcoins_utxos
                .iter()
                .map(|isc_osc_u| (*isc_osc_u.0.unwrap(), isc_osc_u.2.clone()))
                .collect::<Vec<(&IncomingSwapCoin, ListUnspentResultEntry)>>(),
            outgoing_swapcoins_utxos
                .iter()
                .map(|isc_osc_u| (*isc_osc_u.1.unwrap(), isc_osc_u.2.clone()))
                .collect::<Vec<(&OutgoingSwapCoin, ListUnspentResultEntry)>>(),
        ))
    }

    /// Finds the next unused index in the HD keychain.
    pub(super) fn find_hd_next_index(&self, keychain: KeychainKind) -> Result<u32, WalletError> {
        let mut max_index: i32 = -1;
        let all_utxos = self.get_all_utxo()?;
        let mut utxos = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        utxos.append(&mut swap_coin_utxo);

        for (utxo, _) in utxos {
            if utxo.descriptor.is_none() {
                continue;
            }
            let descriptor = utxo.descriptor.expect("its not none");
            let ret = get_hd_path_from_descriptor(&descriptor);
            if ret.is_none() {
                continue;
            }
            let (_, addr_type, index) = ret.expect("its not none");
            if addr_type != keychain.index_num() {
                continue;
            }
            max_index = std::cmp::max(max_index, index);
        }
        Ok((max_index + 1) as u32)
    }

    /// Gets the next external address from the HD keychain.
    pub fn get_next_external_address(&mut self) -> Result<Address, WalletError> {
        let descriptors = self.get_wallet_descriptors()?;
        let receive_branch_descriptor = descriptors
            .get(&KeychainKind::External)
            .expect("external keychain expected");
        let receive_address = self.rpc.derive_addresses(
            receive_branch_descriptor,
            Some([self.store.external_index, self.store.external_index]),
        )?[0]
            .clone();
        self.update_external_index(self.store.external_index + 1)?;
        Ok(receive_address.assume_checked())
    }

    /// Gets the next internal addresses from the HD keychain.
    pub fn get_next_internal_addresses(&self, count: u32) -> Result<Vec<Address>, WalletError> {
        let next_change_addr_index = self.find_hd_next_index(KeychainKind::Internal)?;
        let descriptors = self.get_wallet_descriptors()?;
        let change_branch_descriptor = descriptors
            .get(&KeychainKind::Internal)
            .expect("Internal Keychain expected");
        let addresses = self.rpc.derive_addresses(
            change_branch_descriptor,
            Some([next_change_addr_index, next_change_addr_index + count]),
        )?;

        Ok(addresses
            .into_iter()
            .map(|addrs| addrs.assume_checked())
            .collect())
    }

    /// Refreshes the offer maximum size cache based on the current wallet's unspent transaction outputs (UTXOs).
    pub fn refresh_offer_maxsize_cache(&mut self) -> Result<(), WalletError> {
        let all_utxos = self.get_all_utxo()?;
        let mut utxos = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        utxos.append(&mut swap_coin_utxo);
        let balance: Amount = utxos.iter().fold(Amount::ZERO, |acc, u| acc + u.0.amount);
        self.store.offer_maxsize = balance.to_sat();
        Ok(())
    }

    /// Gets the offer maximum size from the cached value.
    pub fn get_offer_maxsize(&self) -> u64 {
        self.store.offer_maxsize
    }

    /// Gets a tweakable key pair from the master key of the wallet.
    pub fn get_tweakable_keypair(&self) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let privkey = self
            .store
            .master_key
            .derive_priv(&secp, &[ChildNumber::from_hardened_idx(0).unwrap()])
            .unwrap()
            .private_key;

        let public_key = PublicKey {
            compressed: true,
            inner: privkey.public_key(&secp),
        };
        (privkey, public_key)
    }

    /// Signs a transaction corresponding to the provided UTXO spend information.
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        inputs_info: impl Iterator<Item = UTXOSpendInfo>,
    ) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let master_private_key = self
            .store
            .master_key
            .derive_priv(
                &secp,
                &DerivationPath::from_str(HARDENDED_DERIVATION).unwrap(),
            )
            .unwrap();
        let tx_clone = tx.clone();

        for (ix, (input, input_info)) in tx.input.iter_mut().zip(inputs_info).enumerate() {
            match input_info {
                UTXOSpendInfo::SwapCoin {
                    multisig_redeemscript,
                } => {
                    self.find_incoming_swapcoin(&multisig_redeemscript)
                        .unwrap()
                        .sign_transaction_input(ix, &tx_clone, input, &multisig_redeemscript)
                        .unwrap();
                }
                UTXOSpendInfo::SeedCoin { path, input_value } => {
                    let privkey = master_private_key
                        .derive_priv(&secp, &DerivationPath::from_str(&path).unwrap())
                        .unwrap()
                        .private_key;
                    let pubkey = PublicKey {
                        compressed: true,
                        inner: privkey.public_key(&secp),
                    };
                    let scriptcode = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
                    let sighash = SighashCache::new(&tx_clone)
                        .p2wpkh_signature_hash(
                            ix,
                            &scriptcode,
                            Amount::from_sat(input_value),
                            EcdsaSighashType::All,
                        )
                        .unwrap();
                    //use low-R value signatures for privacy
                    //https://en.bitcoin.it/wiki/Privacy#Wallet_fingerprinting
                    let signature = secp.sign_ecdsa_low_r(
                        &secp256k1::Message::from_digest_slice(&sighash[..]).unwrap(),
                        &privkey,
                    );
                    let mut sig_serialised = signature.serialize_der().to_vec();
                    sig_serialised.push(EcdsaSighashType::All as u8);
                    input.witness.push(sig_serialised);
                    input.witness.push(pubkey.to_bytes());
                }
                UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => self
                    .find_outgoing_swapcoin(&swapcoin_multisig_redeemscript)
                    .unwrap()
                    .sign_timelocked_transaction_input(ix, &tx_clone, input, input_value)
                    .unwrap(),
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => self
                    .find_incoming_swapcoin(&swapcoin_multisig_redeemscript)
                    .unwrap()
                    .sign_hashlocked_transaction_input(ix, &tx_clone, input, input_value)
                    .unwrap(),
                UTXOSpendInfo::FidelityBondCoin { index, input_value } => {
                    let privkey = self.get_fidelity_keypair(index)?.secret_key();
                    let redeemscript = self.get_fidelity_reedemscript(index)?;
                    let sighash = SighashCache::new(&tx_clone)
                        .p2wsh_signature_hash(
                            ix,
                            &redeemscript,
                            Amount::from_sat(input_value),
                            EcdsaSighashType::All,
                        )
                        .unwrap();
                    let sig = secp.sign_ecdsa(
                        &secp256k1::Message::from_digest_slice(&sighash[..]).unwrap(),
                        &privkey,
                    );

                    let mut sig_serialised = sig.serialize_der().to_vec();
                    sig_serialised.push(EcdsaSighashType::All as u8);
                    input.witness.push(sig_serialised);
                    input.witness.push(redeemscript.as_bytes());
                }
            }
        }
        Ok(())
    }

    pub fn coin_select(
        &self,
        amount: Amount,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        let all_utxos = self.get_all_locked_utxo()?;

        let mut seed_coin_utxo = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        seed_coin_utxo.append(&mut swap_coin_utxo);

        // Fetch utxos, filter out existing fidelity coins
        let mut unspents = seed_coin_utxo
            .into_iter()
            .filter(|(_, spend_info)| !matches!(spend_info, UTXOSpendInfo::FidelityBondCoin { .. }))
            .collect::<Vec<_>>();

        unspents.sort_by(|a, b| b.0.amount.cmp(&a.0.amount));

        let mut selected_utxo = Vec::new();
        let mut remaining = amount;

        // the simplest largest first coinselection.
        for unspent in unspents {
            if remaining.checked_sub(unspent.0.amount).is_none() {
                selected_utxo.push(unspent);
                break;
            } else {
                remaining -= unspent.0.amount;
                selected_utxo.push(unspent);
            }
        }
        Ok(selected_utxo)
    }

    pub fn get_utxo(
        &self,
        (txid, vout): (Txid, u32),
    ) -> Result<Option<UTXOSpendInfo>, WalletError> {
        let all_utxos = self.get_all_utxo()?;

        let mut seed_coin_utxo = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        seed_coin_utxo.append(&mut swap_coin_utxo);

        for utxo in seed_coin_utxo {
            if utxo.0.txid == txid && utxo.0.vout == vout {
                return Ok(Some(utxo.1));
            }
        }

        Ok(None)
    }

    fn create_and_import_coinswap_address(
        &mut self,
        other_pubkey: &PublicKey,
    ) -> (Address, SecretKey) {
        let (my_pubkey, my_privkey) = generate_keypair();

        let descriptor = self
            .rpc
            .get_descriptor_info(&format!(
                "wsh(sortedmulti(2,{},{}))",
                my_pubkey, other_pubkey
            ))
            .unwrap()
            .descriptor;
        self.import_descriptors(&[descriptor.clone()], None)
            .unwrap();

        //redeemscript and descriptor show up in `getaddressinfo` only after
        // the address gets outputs on it-
        (
            //TODO should completely avoid derive_addresses
            //because its slower and provides no benefit over using rust-bitcoin
            self.rpc.derive_addresses(&descriptor[..], None).unwrap()[0]
                .clone()
                .assume_checked(),
            my_privkey,
        )
    }

    /// Initialize a Coinswap with the Other party.
    /// Returns, the Funding Transactions, [`OutgoingSwapCoin`]s and the Total Miner fees.
    pub fn initalize_coinswap(
        &mut self,
        total_coinswap_amount: u64,
        other_multisig_pubkeys: &[PublicKey],
        hashlock_pubkeys: &[PublicKey],
        hashvalue: Hash160,
        locktime: u16,
        fee_rate: u64,
    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, u64), WalletError> {
        let (coinswap_addresses, my_multisig_privkeys): (Vec<_>, Vec<_>) = other_multisig_pubkeys
            .iter()
            .map(|other_key| self.create_and_import_coinswap_address(other_key))
            .unzip();

        let create_funding_txes_result =
            self.create_funding_txes(total_coinswap_amount, &coinswap_addresses, fee_rate)?;
        //for sweeping there would be another function, probably
        //probably have an enum called something like SendAmount which can be
        // an integer but also can be Sweep

        //TODO: implement the idea where a maker will send its own privkey back to the
        //taker in this situation, so if a taker gets their own funding txes mined
        //but it turns out the maker cant fulfil the coinswap, then the taker gets both
        //privkeys, so it can try again without wasting any time and only a bit of miner fees

        let mut outgoing_swapcoins = Vec::<OutgoingSwapCoin>::new();
        for (
            (((my_funding_tx, &utxo_index), &my_multisig_privkey), &other_multisig_pubkey),
            hashlock_pubkey,
        ) in create_funding_txes_result
            .funding_txes
            .iter()
            .zip(create_funding_txes_result.payment_output_positions.iter())
            .zip(my_multisig_privkeys.iter())
            .zip(other_multisig_pubkeys.iter())
            .zip(hashlock_pubkeys.iter())
        {
            let (timelock_pubkey, timelock_privkey) = generate_keypair();
            let contract_redeemscript = contract::create_contract_redeemscript(
                hashlock_pubkey,
                &timelock_pubkey,
                &hashvalue,
                &locktime,
            );
            let funding_amount = my_funding_tx.output[utxo_index as usize].value;
            let my_senders_contract_tx = contract::create_senders_contract_tx(
                OutPoint {
                    txid: my_funding_tx.compute_txid(),
                    vout: utxo_index,
                },
                funding_amount.to_sat(),
                &contract_redeemscript,
            );

            // self.import_wallet_contract_redeemscript(&contract_redeemscript)?;
            outgoing_swapcoins.push(OutgoingSwapCoin::new(
                my_multisig_privkey,
                other_multisig_pubkey,
                my_senders_contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount.to_sat(),
            ));
        }

        Ok((
            create_funding_txes_result.funding_txes,
            outgoing_swapcoins,
            create_funding_txes_result.total_miner_fee,
        ))
    }

    /// Imports a watch-only redeem script into the wallet.
    pub fn import_watchonly_redeemscript(
        &self,
        redeemscript: &ScriptBuf,
    ) -> Result<(), WalletError> {
        let spk = redeemscript_to_scriptpubkey(redeemscript);
        let descriptor = self
            .rpc
            .get_descriptor_info(&format!("raw({:x})", spk))
            .unwrap()
            .descriptor;
        self.import_descriptors(&[descriptor], Some(WATCH_ONLY_SWAPCOIN_LABEL.to_string()))
    }

    pub fn descriptors_to_import(&self) -> Result<Vec<String>, WalletError> {
        let mut descriptors_to_import = Vec::new();

        descriptors_to_import.extend(self.get_unimported_wallet_desc()?);

        descriptors_to_import.extend(
            self.store
                .incoming_swapcoins
                .values()
                .map(|sc| {
                    let descriptor_without_checksum = format!(
                        "wsh(sortedmulti(2,{},{}))",
                        sc.get_other_pubkey(),
                        sc.get_my_pubkey()
                    );
                    format!(
                        "{}#{}",
                        descriptor_without_checksum,
                        calc_checksum(&descriptor_without_checksum).unwrap()
                    )
                })
                .collect::<Vec<String>>(),
        );

        descriptors_to_import.extend(
            self.store
                .outgoing_swapcoins
                .values()
                .map(|sc| {
                    let descriptor_without_checksum = format!(
                        "wsh(sortedmulti(2,{},{}))",
                        sc.get_other_pubkey(),
                        sc.get_my_pubkey()
                    );
                    format!(
                        "{}#{}",
                        descriptor_without_checksum,
                        calc_checksum(&descriptor_without_checksum).unwrap()
                    )
                })
                .collect::<Vec<String>>(),
        );

        descriptors_to_import.extend(
            self.store
                .incoming_swapcoins
                .values()
                .map(|sc| {
                    let contract_spk = redeemscript_to_scriptpubkey(&sc.contract_redeemscript);
                    let descriptor_without_checksum = format!("raw({:x})", contract_spk);
                    format!(
                        "{}#{}",
                        descriptor_without_checksum,
                        calc_checksum(&descriptor_without_checksum).unwrap()
                    )
                })
                .collect::<Vec<_>>(),
        );
        descriptors_to_import.extend(
            self.store
                .outgoing_swapcoins
                .values()
                .map(|sc| {
                    let contract_spk = redeemscript_to_scriptpubkey(&sc.contract_redeemscript);
                    let descriptor_without_checksum = format!("raw({:x})", contract_spk);
                    format!(
                        "{}#{}",
                        descriptor_without_checksum,
                        calc_checksum(&descriptor_without_checksum).unwrap()
                    )
                })
                .collect::<Vec<_>>(),
        );

        descriptors_to_import.extend(self.store.fidelity_bond.iter().map(|(_, (_, spk, _))| {
            let descriptor_without_checksum = format!("raw({:x})", spk);
            format!(
                "{}#{}",
                descriptor_without_checksum,
                calc_checksum(&descriptor_without_checksum).unwrap()
            )
        }));

        Ok(descriptors_to_import)
    }
}

//______________________WALLET/FUNDING.rs_______________________________________________________

#[derive(Debug)]
pub struct CreateFundingTxesResult {
    pub funding_txes: Vec<Transaction>,
    pub payment_output_positions: Vec<u32>,
    pub total_miner_fee: u64,
}

impl Wallet {
    // Attempts to create the funding transactions.
    /// Returns Ok(None) if there was no error but the wallet was unable to create funding txes
    pub fn create_funding_txes(
        &self,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let ret = self.create_funding_txes_random_amounts(coinswap_amount, destinations, fee_rate);
        if ret.is_ok() {
            log::info!(target: "wallet", "created funding txes with random amounts");
            return ret;
        }

        let ret = self.create_funding_txes_utxo_max_sends(coinswap_amount, destinations, fee_rate);
        if ret.is_ok() {
            log::info!(target: "wallet", "created funding txes with fully-spending utxos");
            return ret;
        }

        let ret =
            self.create_funding_txes_use_biggest_utxos(coinswap_amount, destinations, fee_rate);
        if ret.is_ok() {
            log::info!(target: "wallet", "created funding txes with using the biggest utxos");
            return ret;
        }

        log::info!(target: "wallet", "failed to create funding txes with any method");
        ret
    }

    fn generate_amount_fractions_without_correction(
        count: usize,
        total_amount: u64,
        lower_limit: u64,
    ) -> Result<Vec<f32>, WalletError> {
        for _ in 0..100000 {
            let mut knives = (1..count)
                .map(|_| (OsRng.next_u32() as f32) / (u32::MAX as f32))
                .collect::<Vec<f32>>();
            knives.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

            let mut fractions = Vec::<f32>::new();
            let mut last: f32 = 1.0;
            for k in knives {
                fractions.push(last - k);
                last = k;
            }
            fractions.push(last);

            if fractions
                .iter()
                .all(|f| *f * (total_amount as f32) > (lower_limit as f32))
            {
                return Ok(fractions);
            }
        }
        Err(WalletError::Protocol(
            "Unable to generate amount fractions, probably amount too small".to_string(),
        ))
    }

    pub fn generate_amount_fractions(
        count: usize,
        total_amount: u64,
    ) -> Result<Vec<u64>, WalletError> {
        let mut output_values = Wallet::generate_amount_fractions_without_correction(
            count,
            total_amount,
            5000, //use 5000 satoshi as the lower limit for now
                  //there should always be enough to pay miner fees
        )?
        .iter()
        .map(|f| (*f * (total_amount as f32)) as u64)
        .collect::<Vec<u64>>();

        //rounding errors mean usually 1 or 2 satoshis are lost, add them back

        //this calculation works like this:
        //o = [a, b, c, ...]             | list of output values
        //t = coinswap amount            | total desired value
        //a' <-- a + (t - (a+b+c+...))   | assign new first output value
        //a' <-- a + (t -a-b-c-...)      | rearrange
        //a' <-- t - b - c -...          |
        *output_values.first_mut().unwrap() =
            total_amount - output_values.iter().skip(1).sum::<u64>();
        assert_eq!(output_values.iter().sum::<u64>(), total_amount);

        Ok(output_values)
    }

    /// This function creates funding txes by
    /// Randomly generating some satoshi amounts and send them into
    /// walletcreatefundedpsbt to create txes that create change
    fn create_funding_txes_random_amounts(
        &self,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let change_addresses = self.get_next_internal_addresses(destinations.len() as u32)?;

        let output_values = Wallet::generate_amount_fractions(destinations.len(), coinswap_amount)?;

        self.lock_unspendable_utxos()?;

        let mut funding_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        let mut total_miner_fee = 0;
        for ((address, &output_value), change_address) in destinations
            .iter()
            .zip(output_values.iter())
            .zip(change_addresses.iter())
        {
            let mut outputs = HashMap::<String, Amount>::new();
            outputs.insert(address.to_string(), Amount::from_sat(output_value));

            let fee = Amount::from_sat(fee_rate);
            let remaining = Amount::from_sat(output_value);
            let selected_utxo = self.coin_select(remaining)?;
            let total_input_amount = selected_utxo.iter().fold(Amount::ZERO, |acc, (unspet, _)| {
                acc.checked_add(unspet.amount)
                    .expect("Amount sum overflowed")
            });
            let change_amount = total_input_amount.checked_sub(remaining + fee);
            let mut tx_outs = vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: address.script_pubkey(),
            }];

            if let Some(change) = change_amount {
                tx_outs.push(TxOut {
                    value: change,
                    script_pubkey: change_address.script_pubkey(),
                });
            }
            let tx_inputs = selected_utxo
                .iter()
                .map(|(unspent, _)| TxIn {
                    previous_output: OutPoint::new(unspent.txid, unspent.vout),
                    sequence: Sequence(0),
                    witness: Witness::new(),
                    script_sig: ScriptBuf::new(),
                })
                .collect::<Vec<_>>();
            let mut funding_tx = Transaction {
                input: tx_inputs,
                output: tx_outs,
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            };
            let mut input_info = selected_utxo
                .iter()
                .map(|(_, spend_info)| spend_info.clone());
            self.sign_transaction(&mut funding_tx, &mut input_info)?;

            self.rpc.lock_unspent(
                &funding_tx
                    .input
                    .iter()
                    .map(|vin| vin.previous_output)
                    .collect::<Vec<OutPoint>>(),
            )?;

            let payment_pos = 0;

            funding_txes.push(funding_tx);
            payment_output_positions.push(payment_pos);
            total_miner_fee += fee_rate;
        }

        Ok(CreateFundingTxesResult {
            funding_txes,
            payment_output_positions,
            total_miner_fee,
        })
    }

    fn create_mostly_sweep_txes_with_one_tx_having_change(
        &self,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
        change_address: &Address,
        utxos: &mut dyn Iterator<Item = (Txid, u32, u64)>, //utxos item is (txid, vout, value)
                                                           //utxos should be sorted by size, largest first
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let mut funding_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        let mut total_miner_fee = 0;

        let mut leftover_coinswap_amount = coinswap_amount;
        let mut destinations_iter = destinations.iter();
        let first_tx_input = utxos.next().unwrap();

        for _ in 0..destinations.len() - 2 {
            let (txid, vout, value) = utxos.next().unwrap();

            let mut outputs = HashMap::<&Address, u64>::new();
            outputs.insert(destinations_iter.next().unwrap(), value);
            let tx_inputs = vec![TxIn {
                previous_output: OutPoint::new(txid, vout),
                sequence: Sequence(0),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            }];
            let mut input_info = iter::once(self.get_utxo((txid, vout))?.unwrap());

            let mut tx_outs = Vec::new();
            for (address, value) in outputs {
                tx_outs.push(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: address.script_pubkey(),
                });
            }
            let mut funding_tx = Transaction {
                input: tx_inputs,
                output: tx_outs,
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            };
            self.sign_transaction(&mut funding_tx, &mut input_info)?;

            leftover_coinswap_amount -= funding_tx.output[0].value.to_sat();

            total_miner_fee += fee_rate;

            funding_txes.push(funding_tx);
            payment_output_positions.push(0);
        }
        let mut tx_inputs = Vec::new();
        let mut input_info = Vec::new();
        let (_leftover_inputs, leftover_inputs_values): (Vec<_>, Vec<_>) = utxos
            .map(|(txid, vout, value)| {
                tx_inputs.push(TxIn {
                    previous_output: OutPoint::new(txid, vout),
                    sequence: Sequence(0),
                    witness: Witness::new(),
                    script_sig: ScriptBuf::new(),
                });
                input_info.push(self.get_utxo((txid, vout)).unwrap().unwrap());
                (
                    CreateRawTransactionInput {
                        txid,
                        vout,
                        sequence: None,
                    },
                    value,
                )
            })
            .unzip();
        let mut outputs = HashMap::<&Address, u64>::new();
        outputs.insert(
            destinations_iter.next().unwrap(),
            leftover_inputs_values.iter().sum::<u64>(),
        );
        let mut tx_outs = Vec::new();
        for (address, value) in outputs {
            tx_outs.push(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: address.script_pubkey(),
            });
        }
        let mut funding_tx = Transaction {
            input: tx_inputs,
            output: tx_outs,
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let mut info = input_info.iter().cloned();
        self.sign_transaction(&mut funding_tx, &mut info)?;

        leftover_coinswap_amount -= funding_tx.output[0].value.to_sat();

        total_miner_fee += fee_rate;

        funding_txes.push(funding_tx);
        payment_output_positions.push(0);

        let (first_txid, first_vout, first_value) = first_tx_input;
        let mut outputs = HashMap::<&Address, u64>::new();
        outputs.insert(destinations_iter.next().unwrap(), leftover_coinswap_amount);

        tx_inputs = Vec::new();
        tx_outs = Vec::new();
        let mut change_amount = first_value;
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(first_txid, first_vout),
            sequence: Sequence(0),
            witness: Witness::new(),
            script_sig: ScriptBuf::new(),
        });
        for (address, value) in outputs {
            change_amount -= value;
            tx_outs.push(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: address.script_pubkey(),
            });
        }
        tx_outs.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_address.script_pubkey(),
        });
        let mut funding_tx = Transaction {
            input: tx_inputs,
            output: tx_outs,
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let mut info = iter::once(self.get_utxo((first_txid, first_vout))?.unwrap());
        self.sign_transaction(&mut funding_tx, &mut info)?;

        total_miner_fee += fee_rate;

        funding_txes.push(funding_tx);
        payment_output_positions.push(1);

        Ok(CreateFundingTxesResult {
            funding_txes,
            payment_output_positions,
            total_miner_fee,
        })
    }

    fn create_funding_txes_utxo_max_sends(
        &self,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        //this function creates funding txes by
        //using walletcreatefundedpsbt for the total amount, and if
        //the number if inputs UTXOs is >number_of_txes then split those inputs into groups
        //across multiple transactions

        let mut outputs = HashMap::<&Address, u64>::new();
        outputs.insert(&destinations[0], coinswap_amount);
        let change_address = self.get_next_internal_addresses(1)?[0].clone();

        self.lock_unspendable_utxos()?;

        let fee = Amount::from_sat(1000);

        let remaining = Amount::from_sat(coinswap_amount);

        let selected_utxo = self.coin_select(remaining + fee)?;

        let total_input_amount = selected_utxo.iter().fold(Amount::ZERO, |acc, (unspet, _)| {
            acc.checked_add(unspet.amount)
                .expect("Amount sum overflowed")
        });

        let change_amount = total_input_amount.checked_sub(remaining + fee);

        let mut tx_outs = vec![TxOut {
            value: Amount::from_sat(coinswap_amount),
            script_pubkey: destinations[0].script_pubkey(),
        }];

        if let Some(change) = change_amount {
            tx_outs.push(TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            });
        }

        let tx_inputs = selected_utxo
            .iter()
            .map(|(unspent, _)| TxIn {
                previous_output: OutPoint::new(unspent.txid, unspent.vout),
                sequence: Sequence(0),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            })
            .collect::<Vec<_>>();

        let mut funding_tx = Transaction {
            input: tx_inputs,
            output: tx_outs,
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };

        let mut input_info = selected_utxo
            .iter()
            .map(|(_, spend_info)| spend_info.clone());
        self.sign_transaction(&mut funding_tx, &mut input_info)?;

        let total_tx_inputs_len = selected_utxo.len();
        if total_tx_inputs_len < destinations.len() {
            return Err(WalletError::Protocol(
                "not enough UTXOs found, cant use this method".to_string(),
            ));
        }

        self.create_mostly_sweep_txes_with_one_tx_having_change(
            coinswap_amount,
            destinations,
            fee_rate,
            &change_address,
            &mut selected_utxo
                .iter()
                .map(|(l, _)| (l.txid, l.vout, l.amount.to_sat())),
        )
    }

    fn create_funding_txes_use_biggest_utxos(
        &self,
        coinswap_amount: u64,
        destinations: &[Address],
        fee_rate: u64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        //this function will pick the top most valuable UTXOs and use them
        //to create funding transactions

        let all_utxos = self.get_all_utxo()?;

        let mut seed_coin_utxo = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        seed_coin_utxo.append(&mut swap_coin_utxo);

        let mut list_unspent_result = seed_coin_utxo;
        if list_unspent_result.len() < destinations.len() {
            return Err(WalletError::Protocol(
                "Not enough UTXOs to create this many funding txes".to_string(),
            ));
        }
        list_unspent_result.sort_by(|(a, _), (b, _)| {
            b.amount
                .to_sat()
                .partial_cmp(&a.amount.to_sat())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut list_unspent_count: Option<usize> = None;
        for ii in destinations.len()..list_unspent_result.len() + 1 {
            let sum = list_unspent_result[..ii]
                .iter()
                .map(|(l, _)| l.amount.to_sat())
                .sum::<u64>();
            if sum > coinswap_amount {
                list_unspent_count = Some(ii);
                break;
            }
        }
        if list_unspent_count.is_none() {
            return Err(WalletError::Protocol(
                "Not enough UTXOs/value to create funding txes".to_string(),
            ));
        }

        let inputs = &list_unspent_result[..list_unspent_count.unwrap()];

        if inputs[1..]
            .iter()
            .map(|(l, _)| l.amount.to_sat())
            .any(|utxo_value| utxo_value > coinswap_amount)
        {
            // TODO: Handle this case
            Err(WalletError::Protocol(
                "Some stupid error that will never occur".to_string(),
            ))
        } else {
            //at most one utxo bigger than the coinswap amount

            let change_address = &self.get_next_internal_addresses(1)?[0];
            self.create_mostly_sweep_txes_with_one_tx_having_change(
                coinswap_amount,
                destinations,
                fee_rate,
                change_address,
                &mut inputs.iter().map(|(list_unspent_entry, _spend_info)| {
                    (
                        list_unspent_entry.txid,
                        list_unspent_entry.vout,
                        list_unspent_entry.amount.to_sat(),
                    )
                }),
            )
        }
    }
}

//_________________________________WALLET/FIDELITY.rs_________________________________________________________________________________

// To (strongly) disincentivize Sybil behavior, the value assessment of the bond
// is based on the (time value of the bond)^x here x is the bond_value_exponent,
// where x > 1.
const BOND_VALUE_EXPONENT: f64 = 1.3;

// Interest rate used when calculating the value of fidelity bonds created
// by locking bitcoins in timelocked addresses
// See also:
// https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#determining-interest-rate-r
// Set as a real number, i.e. 1 = 100% and 0.01 = 1%
const BOND_VALUE_INTEREST_RATE: f64 = 0.015;

/// Constant representing the derivation path for fidelity addresses.
const FIDELITY_DERIVATION_PATH: &str = "m/84'/0'/0'/2";

/// Error structure defining possible fidelity related errors
#[derive(Debug)]
pub enum FidelityError {
    WrongScriptType,
    BondAlreadyExists(u32),
    BondDoesNotExist,
    BondAlreadySpent,
    CertExpired,
    InsufficientFund { available: u64, required: u64 },
}

// impl From<bitcoin::secp256k1::Error> for FidelityError {
//     fn from(value: bitcoin::secp256k1::Error) -> Self {
//         Self::Secp(value)
//     }
// }

// impl From<bitcoin::bip32::Error> for FidelityError {
//     fn from(value: bitcoin::bip32::Error) -> Self {
//         Self::Bip32(value)
//     }
// }

// impl From<bitcoin::consensus::encode::Error> for FidelityError {
//     fn from(value: bitcoin::consensus::encode::Error) -> Self {
//         Self::Encoding(value)
//     }
// }

// impl From<bitcoin::key::Error> for FidelityError {
//     fn from(value: bitcoin::key::Error) -> Self {
//         Self::WrongPubKeyFormat(value.to_string())
//     }
// }

// ------- Fidelity Helper Scripts -------------

/// Create a Fidelity Timelocked redeemscript.
pub fn fidelity_redeemscript(lock_time: &LockTime, pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_lock_time(*lock_time)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

#[allow(unused)]
/// Reads the locktime from a fidelity redeemscript.
pub fn read_locktime_from_fidelity_script(
    redeemscript: &ScriptBuf,
) -> Result<LockTime, FidelityError> {
    if let Some(Ok(Instruction::PushBytes(locktime_bytes))) = redeemscript.instructions().next() {
        let mut u4slice: [u8; 4] = [0; 4];
        u4slice[..locktime_bytes.len()].copy_from_slice(locktime_bytes.as_bytes());
        Ok(LockTime::from_consensus(u32::from_le_bytes(u4slice)))
    } else {
        Err(FidelityError::WrongScriptType)
    }
}

#[allow(unused)]
/// Reads the public key from a fidelity redeemscript.
fn read_pubkey_from_fidelity_script(redeemscript: &ScriptBuf) -> Result<PublicKey, FidelityError> {
    if let Some(Ok(Instruction::PushBytes(pubkey_bytes))) = redeemscript.instructions().nth(3) {
        Ok(PublicKey::from_slice(pubkey_bytes.as_bytes()).unwrap())
    } else {
        Err(FidelityError::WrongScriptType)
    }
}

/// Calculates the theoretical fidelity bond value. Bond value calculation is described in the doc below.
/// https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#financial-mathematics-of-joinmarket-fidelity-bonds
pub fn calculate_fidelity_value(
    value: Amount,          // Bond amount in sats
    locktime: u64,          // Bond locktime timestamp
    confirmation_time: u64, // Confirmation timestamp
    current_time: u64,      // Current timestamp
) -> Amount {
    let sec_in_a_year: f64 = 60.0 * 60.0 * 24.0 * 365.2425; // Gregorian calender year length

    let interest_rate = BOND_VALUE_INTEREST_RATE;
    let lock_period_yr = ((locktime - confirmation_time) as f64) / sec_in_a_year;
    let locktime_yr = (locktime as f64) / sec_in_a_year;
    let currenttime_yr = (current_time as f64) / sec_in_a_year;

    // TODO: This calculation can be simplified
    let exp_rt_m1 = f64::exp_m1(interest_rate * lock_period_yr);
    let exp_rtl_m1 = f64::exp_m1(interest_rate * f64::max(0.0, currenttime_yr - locktime_yr));

    let timevalue = f64::max(0.0, f64::min(1.0, exp_rt_m1) - f64::min(1.0, exp_rtl_m1));

    Amount::from_sat(((value.to_sat() as f64) * timevalue).powf(BOND_VALUE_EXPONENT) as u64)
}

/// Structure describing a Fidelity Bond.
/// Fidelity Bonds are described in https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Hash)]
pub struct FidelityBond {
    pub outpoint: OutPoint,
    pub amount: u64,
    pub lock_time: LockTime,
    pub pubkey: PublicKey,
    // Height at which the bond was confirmed.
    pub conf_height: u32,
    // Cert expiry denoted in multiple of difficulty adjustment period (2016 blocks)
    pub cert_expiry: u64,
}

impl FidelityBond {
    /// get the reedemscript for this bond
    pub fn redeem_script(&self) -> ScriptBuf {
        fidelity_redeemscript(&self.lock_time, &self.pubkey)
    }

    /// Get the script_pubkey for this bond.
    pub fn script_pub_key(&self) -> ScriptBuf {
        redeemscript_to_scriptpubkey(&self.redeem_script())
    }

    /// Generate the bond's certificate hash.
    pub fn generate_cert_hash(&self, onion_addr: String) -> sha256d::Hash {
        let cert_msg_str = format!(
            "fidelity-bond-cert|{}|{}|{}|{}|{}|{}",
            self.outpoint, self.pubkey, self.cert_expiry, self.lock_time, self.amount, onion_addr
        );
        let cert_msg = cert_msg_str.as_bytes();
        let mut btc_signed_msg = Vec::<u8>::new();
        btc_signed_msg.extend("\x18Bitcoin Signed Message:\n".as_bytes());
        btc_signed_msg.push(cert_msg.len() as u8);
        btc_signed_msg.extend(cert_msg);
        sha256d::Hash::hash(&btc_signed_msg)
    }
}

// Wallet APIs related to fidelity bonds.
impl Wallet {
    /// Get a reference to the fidelity bond store
    pub fn get_fidelity_bonds(&self) -> &HashMap<u32, (FidelityBond, ScriptBuf, bool)> {
        &self.store.fidelity_bond
    }

    /// Get the highest value fidelity bond. Returns None, if no bond exists.
    pub fn get_highest_fidelity_index(&self) -> Result<Option<u32>, WalletError> {
        Ok(self
            .store
            .fidelity_bond
            .iter()
            .filter_map(|(i, (_, _, is_spent))| {
                if !is_spent {
                    let value = self.calculate_bond_value(*i).unwrap();
                    Some((i, value))
                } else {
                    None
                }
            })
            .max_by(|a, b| a.1.cmp(&b.1))
            .map(|(i, _)| *i))
    }
    /// Get the [KeyPair] for the fidelity bond at given index.
    pub fn get_fidelity_keypair(&self, index: u32) -> Result<Keypair, WalletError> {
        let secp = Secp256k1::new();

        let derivation_path = DerivationPath::from_str(FIDELITY_DERIVATION_PATH)?;

        let child_derivation_path = derivation_path.child(ChildNumber::Normal { index });

        Ok(self
            .store
            .master_key
            .derive_priv(&secp, &child_derivation_path)?
            .to_keypair(&secp))
    }

    /// Derives the fidelity redeemscript from bond values at given index.
    pub fn get_fidelity_reedemscript(&self, index: u32) -> Result<ScriptBuf, WalletError> {
        let (bond, _, _) = self
            .store
            .fidelity_bond
            .get(&index)
            .ok_or(FidelityError::BondDoesNotExist)?;
        Ok(bond.redeem_script())
    }

    /// Get the next fidelity bond address. If no fidelity bond is created
    /// returned address will be derived from index 0, of the [FIDELITY_DERIVATION_PATH]
    pub fn get_next_fidelity_address(
        &self,
        locktime: LockTime,
    ) -> Result<(u32, Address, PublicKey), WalletError> {
        // Check what was the last fidelity address index.
        // Derive a fidelity address
        let next_index = self
            .store
            .fidelity_bond
            .keys()
            .map(|i| *i + 1)
            .last()
            .unwrap_or(0);

        let fidelity_pubkey = PublicKey {
            compressed: true,
            inner: self.get_fidelity_keypair(next_index)?.public_key(),
        };

        Ok((
            next_index,
            Address::p2wsh(
                fidelity_redeemscript(&locktime, &fidelity_pubkey).as_script(),
                self.store.network,
            ),
            fidelity_pubkey,
        ))
    }

    /// Calculate the theoretical fidelity bond value.
    /// Bond value calculation is described in the document below.
    /// https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#financial-mathematics-of-joinmarket-fidelity-bonds
    pub fn calculate_bond_value(&self, index: u32) -> Result<Amount, WalletError> {
        let (bond, _, _) = self
            .store
            .fidelity_bond
            .get(&index)
            .ok_or(FidelityError::BondDoesNotExist)?;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("This can't error")
            .as_secs();

        let hash = self.rpc.get_block_hash(bond.conf_height as u64)?;

        let confirmation_time = self.rpc.get_block_header_info(&hash)?.time as u64;

        let locktime = match bond.lock_time {
            LockTime::Blocks(blocks) => {
                let tip_hash = self.rpc.get_blockchain_info()?.best_block_hash;
                let (tip_height, tip_time) = {
                    let info = self.rpc.get_block_header_info(&tip_hash)?;
                    (info.height, info.time as u64)
                };
                // Estimated locktime from block height = [current-time + (maturity-height - block-count) * 10 * 60] sec
                tip_time + (((blocks.to_consensus_u32() - (tip_height as u32)) * 10 * 60) as u64)
            }
            LockTime::Seconds(sec) => sec.to_consensus_u32() as u64,
        };

        let bond_value = calculate_fidelity_value(
            Amount::from_sat(bond.amount),
            locktime,
            confirmation_time,
            current_time,
        );

        Ok(bond_value)
    }

    /// Create a new fidelity bond with given amount and locktime.
    /// This functions creates the fidelity transaction, signs and broadcast it.
    /// Upon confirmation it stores the fidelity information in the wallet data.
    pub fn create_fidelity(
        &mut self,
        amount: Amount,
        locktime: LockTime, // The final locktime in blockheight or timestamp
    ) -> Result<u32, WalletError> {
        let (index, fidelity_addr, fidelity_pubkey) = self.get_next_fidelity_address(locktime)?;

        let all_utxos = self.get_all_utxo()?;

        let mut seed_coin_utxo = self.list_descriptor_utxo_spend_info(Some(&all_utxos))?;
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info(Some(&all_utxos))?;
        seed_coin_utxo.append(&mut swap_coin_utxo);

        // Fetch utxos, filter out existing fidelity coins
        let mut unspents = seed_coin_utxo
            .into_iter()
            .filter(|(_, spend_info)| !matches!(spend_info, UTXOSpendInfo::FidelityBondCoin { .. }))
            .collect::<Vec<_>>();

        unspents.sort_by(|a, b| b.0.amount.cmp(&a.0.amount));

        let mut selected_utxo = Vec::new();
        let mut remaining = amount;

        // the simplest largest first coinselection.
        for unspent in unspents {
            if remaining.checked_sub(unspent.0.amount).is_none() {
                selected_utxo.push(unspent);
                break;
            } else {
                remaining -= unspent.0.amount;
                selected_utxo.push(unspent);
            }
        }

        let fee = Amount::from_sat(1000); // TODO: Update this with the feerate

        let total_input_amount = selected_utxo.iter().fold(Amount::ZERO, |acc, (unspet, _)| {
            acc.checked_add(unspet.amount)
                .expect("Amount sum overflowed")
        });

        if total_input_amount < amount {
            return Err((FidelityError::InsufficientFund {
                available: total_input_amount.to_sat(),
                required: amount.to_sat(),
            })
            .into());
        }

        let change_amount = total_input_amount.checked_sub(amount + fee);
        let tx_inputs = selected_utxo
            .iter()
            .map(|(unspent, _)| TxIn {
                previous_output: OutPoint::new(unspent.txid, unspent.vout),
                sequence: Sequence(0),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            })
            .collect::<Vec<_>>();

        let mut tx_outs = vec![TxOut {
            value: amount,
            script_pubkey: fidelity_addr.script_pubkey(),
        }];

        if let Some(change) = change_amount {
            let change_addrs = self.get_next_internal_addresses(1)?[0].script_pubkey();
            tx_outs.push(TxOut {
                value: change,
                script_pubkey: change_addrs,
            });
        }
        let current_height = self.rpc.get_block_count()?;
        let anti_fee_snipping_locktime = LockTime::from_height(current_height as u32)?;

        let mut tx = Transaction {
            input: tx_inputs,
            output: tx_outs,
            lock_time: anti_fee_snipping_locktime,
            version: Version::TWO, // anti-fee-snipping
        };

        let mut input_info = selected_utxo
            .iter()
            .map(|(_, spend_info)| spend_info.clone());
        self.sign_transaction(&mut tx, &mut input_info)?;

        let txid = self.rpc.send_raw_transaction(&tx)?;

        let conf_height = loop {
            if let Ok(get_tx_result) = self.rpc.get_transaction(&txid, None) {
                if let Some(ht) = get_tx_result.info.blockheight {
                    log::info!("Fidelity Bond confirmed at blockheight: {}", ht);
                    break ht;
                } else {
                    log::info!(
                        "Fildelity Transaction {} seen in mempool, waiting for confirmation.",
                        txid
                    );
                    if cfg!(feature = "integration-test") {
                        thread::sleep(Duration::from_secs(1)); // wait for 1 sec in tests
                    } else {
                        thread::sleep(Duration::from_secs(60 * 10)); // wait for 10 mins in prod
                    }

                    continue;
                }
            } else {
                log::info!("Waiting for {} in mempool", txid);
                continue;
            }
        };

        let cert_expiry = self.get_fidelity_expriy()?;

        let bond = FidelityBond {
            outpoint: OutPoint::new(txid, 0),
            amount: amount.to_sat(),
            lock_time: locktime,
            pubkey: fidelity_pubkey,
            conf_height,
            cert_expiry,
        };

        let bond_spk = bond.script_pub_key();

        self.store
            .fidelity_bond
            .insert(index, (bond, bond_spk, false));

        Ok(index)
    }

    /// Redeem a Fidelity Bond.
    /// This functions creates a spending transaction, signs and broadcasts it.
    /// Upon confirmation it marks the bond as `spent` in the wallet data.
    pub fn redeem_fidelity(&mut self, index: u32) -> Result<Txid, WalletError> {
        let (bond, _, is_spent) = self
            .store
            .fidelity_bond
            .get(&index)
            .ok_or(FidelityError::BondDoesNotExist)?;

        if *is_spent {
            return Err(FidelityError::BondAlreadySpent.into());
        }

        // create a spending transaction.
        let txin = TxIn {
            previous_output: bond.outpoint,
            sequence: Sequence(0),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        // TODO take feerate as user input
        let fee = 1000;

        let change_addr = &self.get_next_internal_addresses(1)?[0];

        let txout = TxOut {
            script_pubkey: change_addr.script_pubkey(),
            value: Amount::from_sat(bond.amount - fee),
        };

        let mut tx = Transaction {
            input: vec![txin],
            output: vec![txout],
            lock_time: bond.lock_time,
            version: Version::TWO,
        };

        let utxo_spend_info = UTXOSpendInfo::FidelityBondCoin {
            index,
            input_value: bond.amount,
        };

        self.sign_transaction(&mut tx, vec![utxo_spend_info].into_iter())?;

        let txid = self.rpc.send_raw_transaction(&tx)?;

        let conf_height = loop {
            if let Ok(get_tx_result) = self.rpc.get_transaction(&txid, None) {
                if let Some(ht) = get_tx_result.info.blockheight {
                    log::info!("Fidelity Bond confirmed at blockheight: {}", ht);
                    break ht;
                } else {
                    log::info!(
                        "Fildelity Transaction {} seen in mempool, waiting for confirmation.",
                        txid
                    );

                    if cfg!(feature = "integration-test") {
                        thread::sleep(Duration::from_secs(1)); // wait for 1 sec in tests
                    } else {
                        thread::sleep(Duration::from_secs(60 * 10)); // wait for 10 mins in prod
                    }

                    continue;
                }
            } else {
                log::info!("Waiting for {} in mempool", txid);
                continue;
            }
        };

        log::info!(
            "Fidleity spend txid: {}, confirmed at height : {}",
            txid,
            conf_height
        );

        // mark is_spent
        {
            let (_, _, is_spent) = self
                .store
                .fidelity_bond
                .get_mut(&index)
                .ok_or(FidelityError::BondDoesNotExist)?;

            *is_spent = true;
        }

        Ok(txid)
    }

    /// Generate a [FidelityProof] for bond at a given index and a specific onion address.
    pub fn generate_fidelity_proof(
        &self,
        index: u32,
        maker_addr: String,
    ) -> Result<_FidelityProof, WalletError> {
        // Generate a fidelity bond proof from the fidelity data.
        let (bond, _, is_spent) = self
            .store
            .fidelity_bond
            .get(&index)
            .ok_or(FidelityError::BondDoesNotExist)?;

        if *is_spent {
            return Err(FidelityError::BondAlreadySpent.into());
        }

        let fidelity_privkey = self.get_fidelity_keypair(index)?.secret_key();

        let cert_hash = bond.generate_cert_hash(maker_addr);

        let secp = Secp256k1::new();
        let cert_sig = secp.sign_ecdsa(
            &Message::from_digest_slice(cert_hash.as_byte_array())?,
            &fidelity_privkey,
        );

        Ok(_FidelityProof {
            bond: bond.clone(),
            cert_hash,
            cert_sig,
        })
    }

    /// Verify a [FidelityProof] received from the directory servers.
    pub fn verify_fidelity_proof(
        &self,
        proof: &_FidelityProof,
        onion_addr: String,
    ) -> Result<(), WalletError> {
        if self.is_fidelity_expired(&proof.bond)? {
            return Err(FidelityError::CertExpired.into());
        }

        let cert_message =
            Message::from_digest_slice(proof.bond.generate_cert_hash(onion_addr).as_byte_array())?;

        let secp = Secp256k1::new();

        Ok(secp.verify_ecdsa(&cert_message, &proof.cert_sig, &proof.bond.pubkey.inner)?)
    }

    /// Calculate the expiry value. This depends on the current block height.
    pub fn get_fidelity_expriy(&self) -> Result<u64, WalletError> {
        let current_height = self.rpc.get_block_count()?;
        Ok((current_height + 2) /* safety buffer */ / 2016 + 5)
    }

    /// Extend the expiry of a fidelity bond. This is useful for bonds which are close to their expiry.
    pub fn extend_fidelity_expiry(&mut self, index: u32) -> Result<(), WalletError> {
        let cert_expiry = self.get_fidelity_expriy()?;
        let (bond, _, _) = self
            .store
            .fidelity_bond
            .get_mut(&index)
            .ok_or(FidelityError::BondDoesNotExist)?;

        bond.cert_expiry = cert_expiry;

        Ok(())
    }

    /// Checks if the bond has expired.
    pub fn is_fidelity_expired(&self, bond: &FidelityBond) -> Result<bool, WalletError> {
        // Certificate has expired if current height more than the expiry difficulty period target
        // 1 difficulty period = 2016 blocks
        let current_height = self.rpc.get_block_count()?;
        if current_height > bond.cert_expiry * 2016 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

//_________________________________________WALLET/STORAGE.rs_______________________________________________________________

/// Represents the internal data store for a Bitcoin wallet.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WalletStore {
    /// The file name associated with the wallet store.
    pub(crate) file_name: String,
    /// Network the wallet operates on.
    pub(crate) network: Network,
    /// The master key for the wallet.
    pub(super) master_key: Xpriv,
    /// The external index for the wallet.
    pub(super) external_index: u32,
    /// The maximum size for an offer in the wallet.
    pub(crate) offer_maxsize: u64,
    /// Map of multisig redeemscript to incoming swapcoins.
    pub(super) incoming_swapcoins: HashMap<ScriptBuf, IncomingSwapCoin>,
    /// Map of multisig redeemscript to outgoing swapcoins.
    pub(super) outgoing_swapcoins: HashMap<ScriptBuf, OutgoingSwapCoin>,
    /// Map of prevout to contract redeemscript.
    pub(super) prevout_to_contract_map: HashMap<OutPoint, ScriptBuf>,
    /// Map for all the fidelity bond information. (index, (Bond, script_pubkey, is_spent)).
    pub(super) fidelity_bond: HashMap<u32, (FidelityBond, ScriptBuf, bool)>,
    //TODO: Add last synced height and Wallet birthday.
    pub(super) last_synced_height: Option<u64>,

    pub(super) wallet_birthday: Option<u64>,
}

impl WalletStore {
    /// Initialize a store at a path (if path already exists, it will overwrite it).
    pub fn init(
        file_name: String,
        path: &PathBuf,
        network: Network,
        seedphrase: String,
        passphrase: String,
        wallet_birthday: Option<u64>,
    ) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse(seedphrase)?;
        let seed = mnemonic.to_seed(passphrase);
        let master_key = Xpriv::new_master(network, &seed)?;

        let store = Self {
            file_name,
            network,
            master_key,
            external_index: 0,
            offer_maxsize: 0,
            incoming_swapcoins: HashMap::new(),
            outgoing_swapcoins: HashMap::new(),
            prevout_to_contract_map: HashMap::new(),
            fidelity_bond: HashMap::new(),
            last_synced_height: None,
            wallet_birthday,
        };

        std::fs::create_dir_all(path.parent().expect("Path should NOT be root!"))?;
        // write: overwrites existing file.
        // create: creates new file if doesn't exist.
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let writer = BufWriter::new(file);
        serde_cbor::to_writer(writer, &store)?;

        Ok(store)
    }

    /// Load existing file, updates it, writes it back (errors if path doesn't exist).
    pub fn write_to_disk(&self, path: &PathBuf) -> Result<(), WalletError> {
        let wallet_file = OpenOptions::new().write(true).open(path)?;
        let writer = BufWriter::new(wallet_file);
        Ok(serde_cbor::to_writer(writer, &self)?)
    }

    /// Reads from a path (errors if path doesn't exist).
    pub fn read_from_disk(path: &PathBuf) -> Result<Self, WalletError> {
        let wallet_file = OpenOptions::new().read(true).open(path)?;
        let reader = BufReader::new(wallet_file);
        let store: Self = serde_cbor::from_reader(reader)?;
        Ok(store)
    }
}

//____________________________________WALLET/SWAPCOIN.rs____________________________________________

/// Represents an incoming swapcoin.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IncomingSwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub other_privkey: Option<SecretKey>,
    pub contract_tx: Transaction,
    pub contract_redeemscript: ScriptBuf,
    pub hashlock_privkey: SecretKey,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<Preimage>,
}

/// Represents an outgoing swapcoin.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OutgoingSwapCoin {
    pub my_privkey: SecretKey,
    pub other_pubkey: PublicKey,
    pub contract_tx: Transaction,
    pub contract_redeemscript: ScriptBuf,
    pub timelock_privkey: SecretKey,
    pub funding_amount: u64,
    pub others_contract_sig: Option<Signature>,
    pub hash_preimage: Option<Preimage>,
}

/// Represents a watch-only view of a coinswap between two makers.
//like the Incoming/OutgoingSwapCoin structs but no privkey or signature information
//used by the taker to monitor coinswaps between two makers
#[derive(Debug, Clone)]
pub struct WatchOnlySwapCoin {
    /// Public key of the sender (maker).
    pub sender_pubkey: PublicKey,
    /// Public key of the receiver (maker).
    pub receiver_pubkey: PublicKey,
    /// Transaction representing the coinswap contract.
    pub contract_tx: Transaction,
    /// Redeem script associated with the coinswap contract.
    pub contract_redeemscript: ScriptBuf,
    /// The funding amount of the coinswap.
    pub funding_amount: u64,
}

/// Trait representing common functionality for swap coins.
pub trait SwapCoin {
    /// Get the multisig redeem script.
    fn get_multisig_redeemscript(&self) -> ScriptBuf;
    /// Get the contract transaction.
    fn get_contract_tx(&self) -> Transaction;
    /// Get the contract redeem script.
    fn get_contract_redeemscript(&self) -> ScriptBuf;
    /// Get the timelock public key.
    fn get_timelock_pubkey(&self) -> PublicKey;
    /// Get the timelock value.
    fn get_timelock(&self) -> u16;
    /// Get the hashlock public key.
    fn get_hashlock_pubkey(&self) -> PublicKey;
    /// Get the hash value.
    fn get_hashvalue(&self) -> Hash160;
    /// Get the funding amount.
    fn get_funding_amount(&self) -> u64;
    /// Verify the receiver's signature on the contract transaction.
    fn verify_contract_tx_receiver_sig(&self, sig: &Signature) -> Result<(), WalletError>;
    /// Verify the sender's signature on the contract transaction.
    fn verify_contract_tx_sender_sig(&self, sig: &Signature) -> Result<(), WalletError>;
    /// Apply a private key to the swap coin.
    fn apply_privkey(&mut self, privkey: SecretKey) -> Result<(), WalletError>;
}

/// Trait representing swap coin functionality specific to a wallet.
pub trait WalletSwapCoin: SwapCoin {
    fn get_my_pubkey(&self) -> PublicKey;
    fn get_other_pubkey(&self) -> &PublicKey;
    fn get_fully_signed_contract_tx(&self) -> Result<Transaction, WalletError>;
    fn is_hash_preimage_known(&self) -> bool;
}

macro_rules! impl_walletswapcoin {
    ($coin:ident) => {
        impl WalletSwapCoin for $coin {
            fn get_my_pubkey(&self) -> bitcoin::PublicKey {
                let secp = Secp256k1::new();
                PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
                }
            }

            fn get_other_pubkey(&self) -> &PublicKey {
                &self.other_pubkey
            }

            fn get_fully_signed_contract_tx(&self) -> Result<Transaction, WalletError> {
                if self.others_contract_sig.is_none() {
                    return Err(WalletError::Protocol(
                        "Other's contract signature not known".to_string(),
                    ));
                }
                let my_pubkey = self.get_my_pubkey();
                let multisig_redeemscript =
                    create_multisig_redeemscript(&my_pubkey, &self.other_pubkey);
                let index = 0;
                let secp = Secp256k1::new();
                let sighash = secp256k1::Message::from_digest_slice(
                    &SighashCache::new(&self.contract_tx)
                        .p2wsh_signature_hash(
                            index,
                            &multisig_redeemscript,
                            Amount::from_sat(self.funding_amount),
                            EcdsaSighashType::All,
                        )
                        .map_err(ContractError::Sighash)?[..],
                )
                .map_err(ContractError::Secp)?;
                let sig_mine = Signature {
                    signature: secp.sign_ecdsa(&sighash, &self.my_privkey),
                    sighash_type: EcdsaSighashType::All,
                };

                let mut signed_contract_tx = self.contract_tx.clone();
                apply_two_signatures_to_2of2_multisig_spend(
                    &my_pubkey,
                    &self.other_pubkey,
                    &sig_mine,
                    &self.others_contract_sig.unwrap(),
                    &mut signed_contract_tx.input[index],
                    &multisig_redeemscript,
                );
                Ok(signed_contract_tx)
            }

            fn is_hash_preimage_known(&self) -> bool {
                self.hash_preimage.is_some()
            }
        }
    };
}

macro_rules! impl_swapcoin_getters {
    () => {
        //unwrap() here because previously checked that contract_redeemscript is good
        fn get_timelock_pubkey(&self) -> PublicKey {
            read_timelock_pubkey_from_contract(&self.contract_redeemscript).unwrap()
        }

        fn get_timelock(&self) -> u16 {
            read_contract_locktime(&self.contract_redeemscript).unwrap()
        }

        fn get_hashlock_pubkey(&self) -> PublicKey {
            read_hashlock_pubkey_from_contract(&self.contract_redeemscript).unwrap()
        }

        fn get_hashvalue(&self) -> Hash160 {
            read_hashvalue_from_contract(&self.contract_redeemscript).unwrap()
        }

        fn get_contract_tx(&self) -> Transaction {
            self.contract_tx.clone()
        }

        fn get_contract_redeemscript(&self) -> ScriptBuf {
            self.contract_redeemscript.clone()
        }

        fn get_funding_amount(&self) -> u64 {
            self.funding_amount
        }
    };
}

impl IncomingSwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        hashlock_privkey: SecretKey,
        funding_amount: u64,
    ) -> Self {
        let secp = Secp256k1::new();
        let hashlock_pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &hashlock_privkey),
        };
        assert!(
            hashlock_pubkey == read_hashlock_pubkey_from_contract(&contract_redeemscript).unwrap()
        );
        Self {
            my_privkey,
            other_pubkey,
            other_privkey: None,
            contract_tx,
            contract_redeemscript,
            hashlock_privkey,
            funding_amount,
            others_contract_sig: None,
            hash_preimage: None,
        }
    }

    pub fn sign_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        redeemscript: &Script,
    ) -> Result<(), WalletError> {
        if self.other_privkey.is_none() {
            return Err(WalletError::Protocol(
                "Unable to sign: incomplete coinswap for this input".to_string(),
            ));
        }
        let secp = Secp256k1::new();
        let my_pubkey = self.get_my_pubkey();

        let sighash = secp256k1::Message::from_digest_slice(
            &SighashCache::new(tx)
                .p2wsh_signature_hash(
                    index,
                    redeemscript,
                    Amount::from_sat(self.funding_amount),
                    EcdsaSighashType::All,
                )
                .map_err(ContractError::Sighash)?[..],
        )
        .map_err(ContractError::Secp)?;

        let sig_mine = Signature {
            signature: secp.sign_ecdsa(&sighash, &self.my_privkey),
            sighash_type: EcdsaSighashType::All,
        };
        let sig_other = Signature {
            signature: secp.sign_ecdsa(&sighash, &self.other_privkey.unwrap()),
            sighash_type: EcdsaSighashType::All,
        };

        apply_two_signatures_to_2of2_multisig_spend(
            &my_pubkey,
            &self.other_pubkey,
            &sig_mine,
            &sig_other,
            input,
            redeemscript,
        );
        Ok(())
    }

    pub fn sign_hashlocked_transaction_input_given_preimage(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
        hash_preimage: &[u8],
    ) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let sighash = secp256k1::Message::from_digest_slice(
            &SighashCache::new(tx)
                .p2wsh_signature_hash(
                    index,
                    &self.contract_redeemscript,
                    Amount::from_sat(input_value),
                    EcdsaSighashType::All,
                )
                .map_err(ContractError::Sighash)?[..],
        )
        .map_err(ContractError::Secp)?;

        let sig_hashlock = secp.sign_ecdsa(&sighash, &self.hashlock_privkey);
        let mut sig_hashlock_bytes = sig_hashlock.serialize_der().to_vec();
        sig_hashlock_bytes.push(EcdsaSighashType::All as u8);
        input.witness.push(sig_hashlock_bytes);
        input.witness.push(hash_preimage);
        input.witness.push(self.contract_redeemscript.to_bytes());
        Ok(())
    }

    pub fn sign_hashlocked_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
    ) -> Result<(), WalletError> {
        if self.hash_preimage.is_none() {
            panic!("invalid state, unable to sign: preimage unknown");
        }
        self.sign_hashlocked_transaction_input_given_preimage(
            index,
            tx,
            input,
            input_value,
            &self.hash_preimage.unwrap(),
        )
    }

    pub fn create_hashlock_spend_without_preimage(
        &self,
        destination_address: &Address,
    ) -> Transaction {
        let miner_fee = 136 * 10; //126 vbytes x 10 sat/vb, size calculated using testmempoolaccept
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: self.contract_tx.compute_txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: Sequence(1), //hashlock spends must have 1 because of the `OP_CSV 1`
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: Amount::from_sat(self.contract_tx.output[0].value.to_sat() - miner_fee),
            }],
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let index = 0;
        let preimage = Vec::new();
        self.sign_hashlocked_transaction_input_given_preimage(
            index,
            &tx.clone(),
            &mut tx.input[0],
            self.contract_tx.output[0].value.to_sat(),
            &preimage,
        )
        .unwrap();
        tx
    }

    pub fn verify_contract_tx_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        Ok(verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.other_pubkey,
            &sig.signature,
        )?)
    }
}

impl OutgoingSwapCoin {
    pub fn new(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        timelock_privkey: SecretKey,
        funding_amount: u64,
    ) -> Self {
        let secp = Secp256k1::new();
        let timelock_pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &timelock_privkey),
        };
        assert!(
            timelock_pubkey == read_timelock_pubkey_from_contract(&contract_redeemscript).unwrap()
        );
        Self {
            my_privkey,
            other_pubkey,
            contract_tx,
            contract_redeemscript,
            timelock_privkey,
            funding_amount,
            others_contract_sig: None,
            hash_preimage: None,
        }
    }

    pub fn sign_timelocked_transaction_input(
        &self,
        index: usize,
        tx: &Transaction,
        input: &mut TxIn,
        input_value: u64,
    ) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let sighash = secp256k1::Message::from_digest_slice(
            &SighashCache::new(tx)
                .p2wsh_signature_hash(
                    index,
                    &self.contract_redeemscript,
                    Amount::from_sat(input_value),
                    EcdsaSighashType::All,
                )
                .map_err(ContractError::Sighash)?[..],
        )
        .map_err(ContractError::Secp)?;

        let sig_timelock = secp.sign_ecdsa(&sighash, &self.timelock_privkey);

        let mut sig_timelock_bytes = sig_timelock.serialize_der().to_vec();
        sig_timelock_bytes.push(EcdsaSighashType::All as u8);
        input.witness.push(sig_timelock_bytes);
        input.witness.push(Vec::new());
        input.witness.push(self.contract_redeemscript.to_bytes());
        Ok(())
    }

    pub fn create_timelock_spend(&self, destination_address: &Address) -> Transaction {
        let miner_fee = 128 * 2; //128 vbytes x 2 sat/vb, size calculated using testmempoolaccept
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: self.contract_tx.compute_txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: Sequence(self.get_timelock() as u32),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: Amount::from_sat(self.contract_tx.output[0].value.to_sat() - miner_fee),
            }],
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let index = 0;
        self.sign_timelocked_transaction_input(
            index,
            &tx.clone(),
            &mut tx.input[0],
            self.contract_tx.output[0].value.to_sat(),
        )
        .unwrap();
        tx
    }

    //"_with_my_privkey" as opposed to with other_privkey
    pub fn sign_contract_tx_with_my_privkey(
        &self,
        contract_tx: &Transaction,
    ) -> Result<Signature, WalletError> {
        let multisig_redeemscript = self.get_multisig_redeemscript();
        Ok(sign_contract_tx(
            contract_tx,
            &multisig_redeemscript,
            self.funding_amount,
            &self.my_privkey,
        )?)
    }

    pub fn verify_contract_tx_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        Ok(verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.other_pubkey,
            &sig.signature,
        )?)
    }
}

impl WatchOnlySwapCoin {
    pub fn new(
        multisig_redeemscript: &ScriptBuf,
        receiver_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        funding_amount: u64,
    ) -> Result<WatchOnlySwapCoin, WalletError> {
        let (pubkey1, pubkey2) = read_pubkeys_from_multisig_redeemscript(multisig_redeemscript)?;
        if pubkey1 != receiver_pubkey && pubkey2 != receiver_pubkey {
            return Err(WalletError::Protocol(
                "given sender_pubkey not included in redeemscript".to_string(),
            ));
        }
        let sender_pubkey = if pubkey1 == receiver_pubkey {
            pubkey2
        } else {
            pubkey1
        };
        Ok(WatchOnlySwapCoin {
            sender_pubkey,
            receiver_pubkey,
            contract_tx,
            contract_redeemscript,
            funding_amount,
        })
    }
}

impl_walletswapcoin!(IncomingSwapCoin);
impl_walletswapcoin!(OutgoingSwapCoin);

impl SwapCoin for IncomingSwapCoin {
    impl_swapcoin_getters!();

    fn get_multisig_redeemscript(&self) -> ScriptBuf {
        let secp = Secp256k1::new();
        create_multisig_redeemscript(
            &self.other_pubkey,
            &PublicKey {
                compressed: true,
                inner: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
            },
        )
    }

    fn verify_contract_tx_receiver_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        self.verify_contract_tx_sig(sig)
    }

    fn verify_contract_tx_sender_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        self.verify_contract_tx_sig(sig)
    }

    fn apply_privkey(&mut self, privkey: SecretKey) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
        };
        if pubkey != self.other_pubkey {
            return Err(WalletError::Protocol("not correct privkey".to_string()));
        }
        self.other_privkey = Some(privkey);
        Ok(())
    }
}

impl SwapCoin for OutgoingSwapCoin {
    impl_swapcoin_getters!();

    fn get_multisig_redeemscript(&self) -> ScriptBuf {
        let secp = Secp256k1::new();
        create_multisig_redeemscript(
            &self.other_pubkey,
            &PublicKey {
                compressed: true,
                inner: secp256k1::PublicKey::from_secret_key(&secp, &self.my_privkey),
            },
        )
    }

    fn verify_contract_tx_receiver_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        self.verify_contract_tx_sig(sig)
    }

    fn verify_contract_tx_sender_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        self.verify_contract_tx_sig(sig)
    }

    fn apply_privkey(&mut self, privkey: SecretKey) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
        };
        if pubkey == self.other_pubkey {
            Ok(())
        } else {
            Err(WalletError::Protocol("not correct privkey".to_string()))
        }
    }
}

impl SwapCoin for WatchOnlySwapCoin {
    impl_swapcoin_getters!();

    fn apply_privkey(&mut self, privkey: SecretKey) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
        };
        if pubkey == self.sender_pubkey || pubkey == self.receiver_pubkey {
            Ok(())
        } else {
            Err(WalletError::Protocol("not correct privkey".to_string()))
        }
    }

    fn get_multisig_redeemscript(&self) -> ScriptBuf {
        create_multisig_redeemscript(&self.sender_pubkey, &self.receiver_pubkey)
    }

    /*
    Potential confusion here:
        verify sender sig uses the receiver_pubkey
        verify receiver sig uses the sender_pubkey
    */
    fn verify_contract_tx_sender_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        Ok(verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.receiver_pubkey,
            &sig.signature,
        )?)
    }

    fn verify_contract_tx_receiver_sig(&self, sig: &Signature) -> Result<(), WalletError> {
        Ok(verify_contract_tx_sig(
            &self.contract_tx,
            &self.get_multisig_redeemscript(),
            self.funding_amount,
            &self.sender_pubkey,
            &sig.signature,
        )?)
    }
}

//_________________________________WALLET/RPC.rs___________________________________________________________

/// Configuration parameters for connecting to a Bitcoin node via RPC.
#[derive(Debug, Clone)]
pub struct RPCConfig {
    /// The bitcoin node url
    pub url: String,
    /// The bitcoin node authentication mechanism
    pub auth: Auth,
    /// The network we are using (it will be checked the bitcoin node network matches this)
    pub network: Network,
    /// The wallet name in the bitcoin node, derive this from the descriptor.
    pub wallet_name: String,
}

const RPC_HOSTPORT: &str = "localhost:18443";

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            url: RPC_HOSTPORT.to_string(),
            auth: Auth::UserPass("regtestrpcuser".to_string(), "regtestrpcpass".to_string()),
            network: Network::Regtest,
            wallet_name: "random-wallet-name".to_string(),
        }
    }
}

impl TryFrom<&RPCConfig> for Client {
    type Error = WalletError;
    fn try_from(config: &RPCConfig) -> Result<Self, WalletError> {
        let rpc = Client::new(
            format!(
                "http://{}/wallet/{}",
                config.url.as_str(),
                config.wallet_name.as_str()
            )
            .as_str(),
            config.auth.clone(),
        )?;
        if config.network != rpc.get_blockchain_info()?.chain {
            return Err(WalletError::Protocol(
                "RPC Network not mathcing with RPCConfig".to_string(),
            ));
        }
        Ok(rpc)
    }
}

fn list_wallet_dir(client: &Client) -> Result<Vec<String>, WalletError> {
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    #[derive(Deserialize)]
    struct CallResult {
        wallets: Vec<Name>,
    }

    let result: CallResult = client.call("listwalletdir", &[])?;
    Ok(result.wallets.into_iter().map(|n| n.name).collect())
}

impl Wallet {
    /// Sync the wallet with the configured Bitcoin Core RPC. Save data to disk.
    pub fn sync(&mut self) -> Result<(), WalletError> {
        // Create or load the watch-only bitcoin core wallet
        let wallet_name = &self.store.file_name;
        if self.rpc.list_wallets()?.contains(wallet_name) {
            log::info!("wallet already loaded: {}", wallet_name);
        } else if list_wallet_dir(&self.rpc)?.contains(wallet_name) {
            self.rpc.load_wallet(wallet_name)?;
            log::info!("wallet loaded: {}", wallet_name);
        } else {
            // pre-0.21 use legacy wallets
            if self.rpc.version()? < 210_000 {
                self.rpc
                    .create_wallet(wallet_name, Some(true), None, None, None)?;
            } else {
                // TODO: move back to api call when https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/225 is closed
                let args = [
                    Value::String(wallet_name.clone()),
                    Value::Bool(true),  // Disable Private Keys
                    Value::Bool(false), // Create a blank wallet
                    Value::Null,        // Optional Passphrase
                    Value::Bool(false), // Avoid Reuse
                    Value::Bool(true),  // Descriptor Wallet
                ];
                let _: Value = self.rpc.call("createwallet", &args)?;
            }

            log::info!("wallet created: {}", wallet_name);
        }

        let descriptors_to_import = self.descriptors_to_import()?;

        if descriptors_to_import.is_empty() {
            return Ok(());
        }

        log::debug!("Importing Wallet spks/descriptors");

        self.import_descriptors(&descriptors_to_import, None)?;

        // Now run the scan
        log::debug!("Initializing TxOut scan. This may take a while.");

        // Sometimes in test multiple wallet scans can occur at same time, resulting in error.
        // Just retry after 3 sec.
        loop {
            let last_synced_height = self
                .store
                .last_synced_height
                .unwrap_or(0)
                .max(self.store.wallet_birthday.unwrap_or(0));
            let node_synced = self.rpc.get_block_count()?;
            log::info!(
                "rescan_blockchain from:{} to:{}",
                last_synced_height,
                node_synced
            );
            match self.rpc.rescan_blockchain(
                Some(last_synced_height as usize),
                Some(node_synced as usize),
            ) {
                Ok(_) => {
                    self.store.last_synced_height = Some(node_synced);
                    break;
                }

                Err(e) => {
                    log::warn!("Sync Error, Retrying: {}", e);
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            }
        }

        let max_external_index = self.find_hd_next_index(KeychainKind::External)?;
        self.update_external_index(max_external_index)?;
        Ok(())
    }

    /// Import watch addresses into core wallet. Does not check if the address was already imported.
    pub fn import_descriptors(
        &self,
        descriptors_to_import: &[String],
        address_label: Option<String>,
    ) -> Result<(), WalletError> {
        let address_label = address_label.unwrap_or(self.get_core_wallet_label());

        let import_requests = descriptors_to_import
            .iter()
            .map(|desc| {
                if desc.contains("/*") {
                    return json!({
                        "timestamp": "now",
                        "desc": desc,
                        "range": (self.get_addrss_import_count() - 1)
                    });
                }
                json!({
                    "timestamp": "now",
                    "desc": desc,
                    "label": address_label
                })
            })
            .collect();
        let _res: Vec<Value> = self
            .rpc
            .call("importdescriptors", &[import_requests])
            .unwrap();
        Ok(())
    }
}

//___________________________________________WALLET/DIRECT_SEND.rs________________________________________________________

/// Enum representing different options for the amount to be sent in a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum SendAmount {
    Max,
    Amount(Amount),
}

impl FromStr for SendAmount {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "max" {
            SendAmount::Max
        } else {
            SendAmount::Amount(Amount::from_sat(String::from(s).parse::<u64>()?))
        })
    }
}

/// Enum representing different destination options for a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    Wallet,
    Address(Address),
}

impl FromStr for Destination {
    type Err = bitcoin::address::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "wallet" {
            Destination::Wallet
        } else {
            Destination::Address(Address::from_str(s)?.assume_checked())
        })
    }
}

/// Enum representing different ways to identify a coin to spend.
#[derive(Debug, Clone, PartialEq)]
pub enum CoinToSpend {
    LongForm(OutPoint),
    ShortForm {
        prefix: String,
        suffix: String,
        vout: u32,
    },
}

fn parse_short_form_coin(s: &str) -> Option<CoinToSpend> {
    //example short form: 568a4e..83a2e8:0
    if s.len() < 15 {
        return None;
    }
    let dots = &s[6..8];
    if dots != ".." {
        return None;
    }
    let colon = s.chars().nth(14).unwrap();
    if colon != ':' {
        return None;
    }
    let prefix = String::from(&s[0..6]);
    let suffix = String::from(&s[8..14]);
    let vout = s[15..].parse::<u32>().ok()?;
    Some(CoinToSpend::ShortForm {
        prefix,
        suffix,
        vout,
    })
}

impl FromStr for CoinToSpend {
    type Err = bitcoin::blockdata::transaction::ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed_outpoint = OutPoint::from_str(s);
        if let Ok(op) = parsed_outpoint {
            Ok(CoinToSpend::LongForm(op))
        } else {
            let short_form = parse_short_form_coin(s);
            if let Some(cointospend) = short_form {
                Ok(cointospend)
            } else {
                Err(parsed_outpoint.err().unwrap())
            }
        }
    }
}

impl Wallet {
    /// API to perform spending from wallet utxos, Including descriptor coins, swap coins or contract outputs (timelock/hashlock).
    /// This should not be used to spend the Fidelity Bond. Check [Wallet::redeem_fidelity] for fidelity spending.
    ///
    /// The caller needs to specify the list of utxo data and their corresponding spend_info. These can be extracted by various `list_utxo_*` Wallet APIs.
    ///
    /// Caller needs to specify a total Fee and Destination address. Using [Destination::Wallet] will create a transaction to an internal wallet change address.
    ///
    /// Using [SendAmount::Max] will sweep all the inputs, creating a transaction of max possible value to destination. To send custom value and hold remaining in
    /// a change address, use [SendAmount::Amount].
    pub fn spend_from_wallet(
        &mut self,
        fee: Amount,
        send_amount: SendAmount,
        destination: Destination,
        coins_to_spend: &[(ListUnspentResultEntry, UTXOSpendInfo)],
    ) -> Result<Transaction, WalletError> {
        log::info!("Creating Direct-Spend from Wallet.");
        let mut tx_inputs = Vec::<TxIn>::new();
        let mut spend_infos = Vec::new();
        let mut total_input_value = Amount::ZERO;

        for (utxo_data, spend_info) in coins_to_spend {
            // Sequence value required if utxo is timelock/hashlock
            let sequence = match spend_info {
                UTXOSpendInfo::TimelockContract {
                    ref swapcoin_multisig_redeemscript,
                    input_value: _,
                } => self
                    .find_outgoing_swapcoin(swapcoin_multisig_redeemscript)
                    .unwrap()
                    .get_timelock() as u32,
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript: _,
                    input_value: _,
                } => 1, //hashlock spends must have 1 because of the `OP_CSV 1`
                _ => 0,
            };

            tx_inputs.push(TxIn {
                previous_output: OutPoint::new(utxo_data.txid, utxo_data.vout),
                sequence: Sequence(sequence),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            });

            spend_infos.push(spend_info);

            total_input_value += utxo_data.amount;
        }

        if tx_inputs.len() != coins_to_spend.len() {
            return Err(WalletError::Protocol(
                "Could not fetch all inputs.".to_string(),
            ));
        }

        log::info!("Total Input Amount: {} | Fees: {}", total_input_value, fee);

        let dest_addr = match destination {
            Destination::Wallet => self.get_next_external_address()?,
            Destination::Address(a) => {
                //testnet and signet addresses have the same vbyte
                //so a.network is always testnet even if the address is signet
                let testnet_signet_type = (a.as_unchecked().is_valid_for_network(Network::Testnet)
                    || a.as_unchecked().is_valid_for_network(Network::Signet))
                    && (self.store.network == Network::Testnet
                        || self.store.network == Network::Signet);
                if !a.as_unchecked().is_valid_for_network(self.store.network)
                    && !testnet_signet_type
                {
                    return Err(WalletError::Protocol(
                        "Wrong address type in destinations.".to_string(),
                    ));
                }
                a
            }
        };

        let mut output = Vec::<TxOut>::new();

        let txout = {
            let value = match send_amount {
                SendAmount::Max => (total_input_value - fee).to_sat(),
                SendAmount::Amount(a) => a.to_sat(),
            };
            log::info!("Sending {} to {}.", value, dest_addr);
            TxOut {
                script_pubkey: dest_addr.script_pubkey(),
                value: Amount::from_sat(value),
            }
        };

        output.push(txout);

        // Only include change if remaining > dust
        if let SendAmount::Amount(amount) = send_amount {
            let internal_spk = self.get_next_internal_addresses(1)?[0].script_pubkey();
            let remaining = total_input_value - amount - fee;
            if remaining > internal_spk.minimal_non_dust() {
                log::info!("Adding Change {}:{}", internal_spk, remaining);
                output.push(TxOut {
                    script_pubkey: internal_spk,
                    value: remaining,
                });
            }
        }

        // Set the Anti-Fee-Snipping locktime
        let lock_time = LockTime::from_height(self.rpc.get_block_count().unwrap() as u32).unwrap();

        let mut tx = Transaction {
            input: tx_inputs,
            output,
            lock_time,
            version: Version::TWO,
        };
        self.sign_transaction(
            &mut tx,
            &mut coins_to_spend.iter().map(|(_, usi)| usi.clone()),
        )?;
        log::debug!("Signed Transaction : {:?}", tx.raw_hex());
        Ok(tx)
    }
}

//_______________________________WALLET/ERROR.rs__________________________________________________________________

/// Enum for handling wallet-related errors.
#[derive(Debug)]
pub enum WalletError {
    File(std::io::Error),
    Cbor(serde_cbor::Error),
    Rpc(bitcoind::bitcoincore_rpc::Error),
    Protocol(String),
    BIP32(bitcoin::bip32::Error),
    BIP39(bip39::Error),
    Contract(ContractError),
    Fidelity(FidelityError),
    Locktime(bitcoin::blockdata::locktime::absolute::ConversionError),
    Secp(bitcoin::secp256k1::Error),
}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        Self::File(e)
    }
}

impl From<bitcoind::bitcoincore_rpc::Error> for WalletError {
    fn from(value: bitcoind::bitcoincore_rpc::Error) -> Self {
        Self::Rpc(value)
    }
}

impl From<bitcoin::bip32::Error> for WalletError {
    fn from(value: bitcoin::bip32::Error) -> Self {
        Self::BIP32(value)
    }
}

impl From<bip39::Error> for WalletError {
    fn from(value: bip39::Error) -> Self {
        Self::BIP39(value)
    }
}

impl From<ContractError> for WalletError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<serde_cbor::Error> for WalletError {
    fn from(value: serde_cbor::Error) -> Self {
        Self::Cbor(value)
    }
}

impl From<FidelityError> for WalletError {
    fn from(value: FidelityError) -> Self {
        Self::Fidelity(value)
    }
}

impl From<bitcoin::blockdata::locktime::absolute::ConversionError> for WalletError {
    fn from(value: bitcoin::blockdata::locktime::absolute::ConversionError) -> Self {
        Self::Locktime(value)
    }
}

impl From<bitcoin::secp256k1::Error> for WalletError {
    fn from(value: bitcoin::secp256k1::Error) -> Self {
        Self::Secp(value)
    }
}

// impl From<bitcoin::address::Error> for WalletError {
//     fn from(value: bitcoin::address::Error) -> Self {
//         Self::Address(value)
//     }
// }

// Other things required from outside the wallet module->

/// Contains proof data related to fidelity bond.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Hash)]
pub struct _FidelityProof {
    pub bond: FidelityBond,
    pub cert_hash: doublesha,
    pub cert_sig: bitcoin::secp256k1::ecdsa::Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::PrivateKey;
    use bitcoind::tempfile::tempdir;

    #[test]
    fn test_send_amount_parsing() {
        assert_eq!(SendAmount::from_str("max").unwrap(), SendAmount::Max);
        assert_eq!(
            SendAmount::from_str("1000").unwrap(),
            SendAmount::Amount(Amount::from_sat(1000))
        );
        assert_ne!(
            SendAmount::from_str("1000").unwrap(),
            SendAmount::from_str("100").unwrap()
        );
        assert!(SendAmount::from_str("not a number").is_err());
    }

    #[test]
    fn test_destination_parsing() {
        assert_eq!(
            Destination::from_str("wallet").unwrap(),
            Destination::Wallet
        );
        let address1 = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf";
        assert!(matches!(
            Destination::from_str(address1),
            Ok(Destination::Address(_))
        ));

        let address1 = Destination::Address(
            Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf")
                .unwrap()
                .assume_checked(),
        );

        let address2 = Destination::Address(
            Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
                .unwrap()
                .assume_checked(),
        );
        assert_ne!(address1, address2);
        assert!(Destination::from_str("invalid address").is_err());
    }

    #[test]
    fn test_coin_to_spend_long_form_and_short_form_parsing() {
        let valid_outpoint_str =
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0";
        let coin_to_spend_long_form = CoinToSpend::LongForm(OutPoint {
            txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                .parse()
                .unwrap(),
            vout: 0,
        });
        assert_eq!(
            CoinToSpend::from_str(valid_outpoint_str).unwrap(),
            coin_to_spend_long_form
        );
        let valid_outpoint_str =
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1";
        assert_ne!(
            CoinToSpend::from_str(valid_outpoint_str).unwrap(),
            coin_to_spend_long_form
        );

        let valid_short_form_str = "123abc..def456:0";
        assert!(matches!(
            CoinToSpend::from_str(valid_short_form_str),
            Ok(CoinToSpend::ShortForm { .. })
        ));
        let mut invalid_short_form_str = "123ab..def456:0";
        assert!(CoinToSpend::from_str(invalid_short_form_str).is_err());

        invalid_short_form_str = "123abc.def456:0";
        assert!(CoinToSpend::from_str(invalid_short_form_str).is_err());

        invalid_short_form_str = "123abc..def4560";
        assert!(CoinToSpend::from_str(invalid_short_form_str).is_err());

        assert!(CoinToSpend::from_str("invalid").is_err());
    }

    //___________________________________________________________________FIDELITY_TESTS___________________________________

    #[test]
    fn test_fidelity_bond_value_function_behavior() {
        const EPSILON: f64 = 0.000001;
        const YEAR: f64 = 60.0 * 60.0 * 24.0 * 365.2425;

        //the function should be flat anywhere before the locktime ends
        let values = (0..4)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (6.0 * YEAR) as u64,
                    0,
                    y * (YEAR as u64),
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i + 1] - values[i])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(v.abs() < EPSILON);
        }

        //after locktime, the value should go down
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (6.0 * YEAR) as u64,
                    0,
                    (6 + y) * (YEAR as u64),
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i + 1] - values[i])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(*v < 0.0);
        }

        //value of a bond goes up as the locktime goes up
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    ((y as f64) * YEAR) as u64,
                    0,
                    0,
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_ratio = (0..values.len() - 1)
            .map(|i| values[i] / values[i + 1])
            .collect::<Vec<f64>>();
        let value_ratio_diff = (0..value_ratio.len() - 1)
            .map(|i| value_ratio[i] - value_ratio[i + 1])
            .collect::<Vec<f64>>();
        for v in &value_ratio_diff {
            assert!(*v < 0.0);
        }

        //value of a bond locked into the far future is constant, clamped at the value of burned coins
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (((200 + y) as f64) * YEAR) as u64,
                    0,
                    0,
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i] - values[i + 1])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(v.abs() < EPSILON);
        }
    }

    #[test]
    fn test_fidelity_bond_values() {
        let value = Amount::from_btc(1.0).unwrap();
        let confirmation_time = 50_000;
        let current_time = 60_000;

        // Following is a (locktime, fidelity_value) tupple series to show how fidelity_value increases with locktimes
        let test_vectors = [
            (55000, 0), // Value is zero for expired timelocks
            (60000, 3020),
            (65000, 5117),
            (70000, 7437),
            (75000, 9940),
            (80000, 12599),
            (85000, 15395),
            (90000, 18313),
            (95000, 21344),
            (100000, 24477),
            (105000, 27706),
            (110000, 31024),
            (115000, 34426),
            (120000, 37908),
            (125000, 41465),
            (130000, 45094),
            (135000, 48792),
            (140000, 52556),
            (145000, 56383),
        ]
        .map(|(lt, val)| (lt as u64, Amount::from_sat(val)));

        for (locktime, fidelity_value) in test_vectors {
            assert_eq!(
                fidelity_value,
                calculate_fidelity_value(value, locktime, confirmation_time, current_time)
            );
        }
    }

    #[test]
    fn test_fidleity_redeemscripts() {
        let test_data = [
            (
                ("03ffe2b8b46eb21eadc3b535e9f57054213a1775b035faba6c5b3368b3a0ab5a5c", 15000),
                "02983ab1752103ffe2b8b46eb21eadc3b535e9f57054213a1775b035faba6c5b3368b3a0ab5a5cac",
            ),
            (
                ("031499764842691088897cff51efd85347dd3215912cbb8fb9b121b1da3b15bec8", 30000),
                "023075b17521031499764842691088897cff51efd85347dd3215912cbb8fb9b121b1da3b15bec8ac",
            ),
            (
                ("022714334f189db14fabd3dd893bbb913b8c3ddff245f7094cdc0b24c2fabb3570", 45000),
                "03c8af00b17521022714334f189db14fabd3dd893bbb913b8c3ddff245f7094cdc0b24c2fabb3570ac",
            ),
            (
                ("02145a1d2bd118edcb3fe85495192d44e1d09f75ab4f0fe98269f61ff672860dae", 60000),
                "0360ea00b1752102145a1d2bd118edcb3fe85495192d44e1d09f75ab4f0fe98269f61ff672860daeac",
            ),
        ].map(|((pk, lt), script)| (
            (PublicKey::from_str(pk).unwrap(), LockTime::from_height(lt).unwrap()),
            ScriptBuf::from_hex(script).unwrap(),
        ));

        for ((pk, lt), script) in test_data {
            assert_eq!(script, fidelity_redeemscript(&lt, &pk));
            assert_eq!(pk, read_pubkey_from_fidelity_script(&script).unwrap());
            assert_eq!(lt, read_locktime_from_fidelity_script(&script).unwrap());
        }
    }

    //______________________________________________STORAGE tests__________________________________________________________________

    #[test]
    fn test_write_and_read_wallet_to_disk() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_wallet.cbor");
        let mnemonic = Mnemonic::generate(12).unwrap().to_string();

        let original_wallet_store = WalletStore::init(
            "test_wallet".to_string(),
            &file_path,
            Network::Bitcoin,
            mnemonic,
            "passphrase".to_string(),
            None,
        )
        .unwrap();

        original_wallet_store.write_to_disk(&file_path).unwrap();

        let read_wallet = WalletStore::read_from_disk(&file_path).unwrap();
        assert_eq!(original_wallet_store, read_wallet);
    }

    //______________________________________________________SWAPCOIN test__________________________________________________________________________

    #[test]
    fn test_apply_privkey_watchonly_swapcoin() {
        let secp = Secp256k1::new();

        let privkey_sender = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        };

        let privkey_receiver = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
        };

        let mut swapcoin = WatchOnlySwapCoin {
            sender_pubkey: PublicKey::from_private_key(&secp, &privkey_sender),
            receiver_pubkey: PublicKey::from_private_key(&secp, &privkey_receiver),
            funding_amount: 100,
            contract_tx: Transaction {
                input: vec![],
                output: vec![],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
        };

        let secret_key_1 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let secret_key_2 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000069")
                .unwrap();
        // Test for applying the correct privkey
        assert!(swapcoin.apply_privkey(secret_key_1).is_ok());
        // Test for applying the incorrect privkey
        assert!(swapcoin.apply_privkey(secret_key_2).is_err());
    }

    #[test]
    fn test_apply_privkey_incoming_swapcoin() {
        let secp = Secp256k1::new();
        let other_privkey = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
        };

        let mut incoming_swapcoin = IncomingSwapCoin {
            my_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            other_privkey: Some(
                secp256k1::SecretKey::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000005",
                )
                .unwrap(),
            ),
            other_pubkey: PublicKey::from_private_key(&secp, &other_privkey),
            contract_tx: Transaction {
                input: vec![],
                output: vec![],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
            hashlock_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
            funding_amount: 0,
            others_contract_sig: None,
            hash_preimage: None,
        };

        let secret_key_1 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let secret_key_2 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000069")
                .unwrap();
        // Test for applying the correct privkey
        assert!(incoming_swapcoin.apply_privkey(secret_key_1).is_ok());
        // Test for applying the incorrect privkey
        assert!(incoming_swapcoin.apply_privkey(secret_key_2).is_err());
        // Test get_other_pubkey
        let other_pubkey_from_method = incoming_swapcoin.get_other_pubkey();
        assert_eq!(other_pubkey_from_method, &incoming_swapcoin.other_pubkey);
        // Test is_hash_preimage_known for empty hash_preimage
        assert!(!incoming_swapcoin.is_hash_preimage_known());
    }

    #[test]

    fn test_apply_privkey_outgoing_swapcoin() {
        let secp = Secp256k1::new();
        let other_privkey = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        };
        let mut outgoing_swapcoin = OutgoingSwapCoin {
            my_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
            other_pubkey: PublicKey::from_private_key(&secp, &other_privkey),
            contract_tx: Transaction {
                input: vec![],
                output: vec![],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
            timelock_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            funding_amount: 0,
            others_contract_sig: None,
            hash_preimage: None,
        };
        let secret_key_1 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let secret_key_2 =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000069")
                .unwrap();

        // Test for applying the correct privkey
        assert!(outgoing_swapcoin.apply_privkey(secret_key_1).is_ok());
        // Test for applying the incorrect privkey
        assert!(outgoing_swapcoin.apply_privkey(secret_key_2).is_err());
        // Test get_other_pubkey
        assert_eq!(
            outgoing_swapcoin.get_other_pubkey(),
            &outgoing_swapcoin.other_pubkey
        );
        // Test is_hash_preimage_known
        assert!(!outgoing_swapcoin.is_hash_preimage_known());
    }

    #[test]
    fn test_sign_transaction_input_fail() {
        let secp = Secp256k1::new();
        let other_privkey = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
        };
        let index: usize = 10;
        let mut input = TxIn::default();
        let tx = Transaction {
            input: vec![input.clone()],
            output: vec![],
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };

        let contract_redeemscript = ScriptBuf::default(); // Example redeem script

        let incoming_swapcoin = IncomingSwapCoin {
            my_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            other_privkey: Some(
                secp256k1::SecretKey::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000005",
                )
                .unwrap(),
            ),
            other_pubkey: PublicKey::from_private_key(&secp, &other_privkey),
            contract_tx: Transaction {
                input: vec![],
                output: vec![],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
            hashlock_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
            funding_amount: 100_000,
            others_contract_sig: None,
            hash_preimage: None,
        };
        // Intentionally failing to sign with incomplete swapcoin
        assert!(incoming_swapcoin
            .sign_transaction_input(index, &tx, &mut input, &contract_redeemscript,)
            .is_err());
        let sign = bitcoin::ecdsa::Signature {
            signature: secp256k1::ecdsa::Signature::from_compact(&[0; 64]).unwrap(),
            sighash_type: bitcoin::sighash::EcdsaSighashType::All,
        };
        // Intentionally failing to verify with incomplete swapcoin
        assert!(incoming_swapcoin
            .verify_contract_tx_sender_sig(&sign)
            .is_err());
    }

    #[test]

    fn test_create_hashlock_spend_without_preimage() {
        let secp = Secp256k1::new();
        let other_privkey = PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        };
        let input = TxIn::default();
        let output = TxOut::NULL;
        let incoming_swapcoin = IncomingSwapCoin {
            my_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            other_privkey: Some(
                secp256k1::SecretKey::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000005",
                )
                .unwrap(),
            ),
            other_pubkey: PublicKey::from_private_key(&secp, &other_privkey),
            contract_tx: Transaction {
                input: vec![input.clone()],
                output: vec![output.clone()],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
            hashlock_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
            funding_amount: 100_000,
            others_contract_sig: None,
            hash_preimage: Some(Preimage::from([0; 32])),
        };
        let destination_address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();

        let miner_fee = 136 * 10; //126 vbytes x 10 sat/vb, size calculated using testmempoolaccept
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: incoming_swapcoin.contract_tx.compute_txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: Sequence(1), //hashlock spends must have 1 because of the `OP_CSV 1`
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: Amount::from_sat(
                    incoming_swapcoin.contract_tx.output[0].value.to_sat() - miner_fee,
                ),
            }],
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let index = 0;
        let preimage = Vec::new();
        incoming_swapcoin
            .sign_hashlocked_transaction_input_given_preimage(
                index,
                &tx.clone(),
                &mut tx.input[0],
                incoming_swapcoin.contract_tx.output[0].value.to_sat(),
                &preimage,
            )
            .unwrap();
        // If the tx is succesful, check some field like:
        assert!(tx.input[0].witness.len() == 3);
    }

    #[test]
    fn test_sign_hashlocked_transaction_input() {
        let secp = Secp256k1::new();
        let other_privkey = PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        };
        let mut input = TxIn::default();
        let output = TxOut::NULL;
        let incoming_swapcoin = IncomingSwapCoin {
            my_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            other_privkey: Some(
                secp256k1::SecretKey::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000005",
                )
                .unwrap(),
            ),
            other_pubkey: PublicKey::from_private_key(&secp, &other_privkey),
            contract_tx: Transaction {
                input: vec![input.clone()],
                output: vec![output.clone()],
                lock_time: LockTime::ZERO,
                version: Version::TWO,
            },
            contract_redeemscript: ScriptBuf::default(),
            hashlock_privkey: secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
            funding_amount: 100_000,
            others_contract_sig: None,
            hash_preimage: Some(Preimage::from([0; 32])),
        };
        let destination_address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();

        let miner_fee = 136 * 10;
        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: incoming_swapcoin.contract_tx.compute_txid(),
                    vout: 0, //contract_tx is one-input-one-output
                },
                sequence: Sequence(1), //hashlock spends must have 1 because of the `OP_CSV 1`
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            }],
            output: vec![TxOut {
                script_pubkey: destination_address.script_pubkey(),
                value: Amount::from_sat(
                    incoming_swapcoin.contract_tx.output[0].value.to_sat() - miner_fee,
                ),
            }],
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };
        let index = 0;
        let input_value = 100;
        let preimage = Vec::new();
        incoming_swapcoin
            .sign_hashlocked_transaction_input_given_preimage(
                index,
                &tx.clone(),
                &mut tx.input[0],
                incoming_swapcoin.contract_tx.output[0].value.to_sat(),
                &preimage,
            )
            .unwrap();
        // Check if the hashlocked transaction input is successful
        let final_return = incoming_swapcoin.sign_hashlocked_transaction_input(
            index,
            &tx,
            &mut input,
            input_value,
        );
        assert!(final_return.is_ok());
    }
}
