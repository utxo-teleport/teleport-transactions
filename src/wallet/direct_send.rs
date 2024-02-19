//! Send regular Bitcoin payments.
//!
//! This module provides functionality for managing wallet transactions, including the creation of
//! direct sends. It leverages Bitcoin Core's RPC for wallet synchronization and implements various
//! parsing mechanisms for transaction inputs and outputs.

use std::{num::ParseIntError, str::FromStr};

use bitcoin::{
    absolute::LockTime, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoind::bitcoincore_rpc::RpcApi;

use crate::wallet::{api::UTXOSpendInfo, SwapCoin};

use super::{error::WalletError, Wallet};

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
    type Err = bitcoin::address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "wallet" {
            Destination::Wallet
        } else {
            Destination::Address(Address::from_str(s)?.assume_checked())
        })
    }
}

/// Enum representing different errors that can occur when parsing a coin to spend.
#[derive(Debug, PartialEq)]
pub enum ParseCoinError {
    ErrorMessage(String),
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

/*    Short-form coin example format:
        prefix : 123abc
        dots   : ..
        suffix : def456
        vout   : 0
*/
fn parse_short_form_coin(s: &str) -> Result<CoinToSpend, ParseCoinError> {
    if s.len() == 16 {
        let dots = &s[6..8];
        if dots != ".." {
            return Err(ParseCoinError::ErrorMessage(
                "Coin to spend (short form) has invalid dots!".to_string(),
            ));
        }
        let colon = s.chars().nth(14).unwrap();
        if colon != ':' {
            return Err(ParseCoinError::ErrorMessage(
                "Coin to spend (short form) has invalid colon!".to_string(),
            ));
        }
        let prefix = String::from(&s[0..6]);
        let suffix = String::from(&s[8..14]);
        let vout = s[15..]
            .parse::<u32>()
            .map_err(|e| ParseCoinError::ErrorMessage(e.to_string()))?;
        Ok(CoinToSpend::ShortForm {
            prefix,
            suffix,
            vout,
        })
    } else {
        Err(ParseCoinError::ErrorMessage(
            "Coin to spend (short form) has invalid length!".to_string(),
        ))
    }
}

impl FromStr for CoinToSpend {
    type Err = bitcoin::blockdata::transaction::ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed_outpoint = OutPoint::from_str(s);
        if let Ok(op) = parsed_outpoint {
            Ok(CoinToSpend::LongForm(op))
        } else {
            let short_form = parse_short_form_coin(s);
            if let Ok(cointospend) = short_form {
                Ok(cointospend)
            } else {
                Err(parsed_outpoint.err().unwrap())
            }
        }
    }
}

impl Wallet {
    pub fn create_direct_send(
        &mut self,
        fee_rate: u64,
        send_amount: SendAmount,
        destination: Destination,
        coins_to_spend: &[CoinToSpend],
    ) -> Result<Transaction, WalletError> {
        let mut tx_inputs = Vec::<TxIn>::new();
        let mut unspent_inputs = Vec::new();

        //TODO this search within a search could get very slow
        // Filter out fidelity bonds. Use `wallet.redeem_fidelity()` function to spend fidelity bond coins.
        let list_unspent_result = self
            .list_unspent_from_wallet(true, true)?
            .into_iter()
            .filter(|(_, info)| !matches!(info, UTXOSpendInfo::FidelityBondCoin { .. }))
            .collect::<Vec<_>>();

        for (list_unspent_entry, spend_info) in list_unspent_result {
            for cts in coins_to_spend {
                let previous_output = match cts {
                    CoinToSpend::LongForm(outpoint) => {
                        if list_unspent_entry.txid == outpoint.txid
                            && list_unspent_entry.vout == outpoint.vout
                        {
                            *outpoint
                        } else {
                            continue;
                        }
                    }
                    CoinToSpend::ShortForm {
                        prefix,
                        suffix,
                        vout,
                    } => {
                        let txid_hex = list_unspent_entry.txid.to_string();
                        if txid_hex.starts_with(prefix)
                            && txid_hex.ends_with(suffix)
                            && list_unspent_entry.vout == *vout
                        {
                            OutPoint {
                                txid: list_unspent_entry.txid,
                                vout: list_unspent_entry.vout,
                            }
                        } else {
                            continue;
                        }
                    }
                };
                log::debug!("found coin to spend = {:?}", previous_output);

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
                    previous_output,
                    sequence: Sequence(sequence),
                    witness: Witness::new(),
                    script_sig: ScriptBuf::new(),
                });
                unspent_inputs.push((list_unspent_entry.clone(), spend_info.clone()));
            }
        }
        if tx_inputs.len() != coins_to_spend.len() {
            panic!(
                "unable to find all given inputs, only found = {:?}",
                tx_inputs
            );
        }

        let dest_addr = match destination {
            Destination::Wallet => self.get_next_external_address()?,
            Destination::Address(a) => {
                //testnet and signet addresses have the same vbyte
                //so a.network is always testnet even if the address is signet
                let testnet_signet_type = (a.network == Network::Testnet
                    || a.network == Network::Signet)
                    && (self.store.network == Network::Testnet
                        || self.store.network == Network::Signet);
                if a.network != self.store.network && !testnet_signet_type {
                    panic!("wrong address network type (e.g. mainnet, testnet, regtest, signet)");
                }
                a
            }
        };
        let miner_fee = 500 * fee_rate / 1000; //TODO this is just a rough estimate now

        let mut output = Vec::<TxOut>::new();
        let total_input_value = unspent_inputs
            .iter()
            .fold(Amount::ZERO, |acc, u| acc + u.0.amount)
            .to_sat();
        output.push(TxOut {
            script_pubkey: dest_addr.script_pubkey(),
            value: match send_amount {
                SendAmount::Max => total_input_value - miner_fee,
                SendAmount::Amount(a) => a.to_sat(),
            },
        });
        if let SendAmount::Amount(amount) = send_amount {
            output.push(TxOut {
                script_pubkey: self.get_next_internal_addresses(1)?[0].script_pubkey(),
                value: total_input_value - amount.to_sat() - miner_fee,
            });
        }

        // Anti fee snipping locktime
        let lock_time = LockTime::from_height(self.rpc.get_block_count().unwrap() as u32).unwrap();

        let mut tx = Transaction {
            input: tx_inputs,
            output,
            lock_time,
            version: 2,
        };
        log::debug!("unsigned transaction = {:#?}", tx);
        self.sign_transaction(
            &mut tx,
            &mut unspent_inputs.iter().map(|(_u, usi)| usi.clone()),
        )?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::rpc;
    use bip39::Mnemonic;
    use bitcoin::Txid;
    use bitcoind::bitcoincore_rpc::Auth;
    use std::path::PathBuf;

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
    }

    #[test]
    fn test_parse_short_form_coin_valid() {
        let coin_str = "123abc..456def:0";
        let expected_coin = CoinToSpend::ShortForm {
            prefix: String::from("123abc"),
            suffix: String::from("456def"),
            vout: 0,
        };
        assert_eq!(parse_short_form_coin(coin_str), Ok(expected_coin));
    }

    #[test]
    fn test_parse_short_form_coin_dots_valid() {
        let coin_str = "123abc..456def:0";
        assert!(matches!(
            CoinToSpend::from_str(coin_str),
            Ok(CoinToSpend::ShortForm { .. })
        ));
    }

    #[test]
    fn test_parse_short_form_coin_dots_invalid() {
        let coin_str = "123abc.456def:0";
        assert!(parse_short_form_coin(coin_str).is_err());
    }

    #[test]
    fn test_parse_short_form_coin_invalid_length() {
        let coin_str = "123abc.456def:0";
        assert!(CoinToSpend::from_str(coin_str).is_err());
    }

    #[test]
    fn test_parse_short_form_coin_vout_missing() {
        let coin_str = "123abc..456def";
        assert!(parse_short_form_coin(coin_str).is_err());
    }

    #[test]
    fn test_parse_short_form_coin_invalid_colon() {
        let coin_str = "123abc..456def0";
        assert!(CoinToSpend::from_str(coin_str).is_err());
    }

    #[test]
    fn test_parse_short_form_coin_invalid_string() {
        let coin_str = "invalid";
        assert!(CoinToSpend::from_str(coin_str).is_err());
    }

    #[test]
    fn test_create_direct_send() {
        let mut path = PathBuf::new();
        path.push("/tmp/teleport/test-wallet-direct-send");

        let rpc_config = rpc::RPCConfig {
            url: "http://localhost:8332".to_string(),
            auth: Auth::UserPass("username".to_string(), "password".to_string()),
            network: Network::Testnet,
            wallet_name: String::from("test-wallet"),
        };
        // let mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let mnemonic_seedphrase = Mnemonic::generate(12).unwrap().to_string();
        let passphrase =
            "abandon ability able about above absent absorb abstract absurd abuse access accident"
                .trim()
                .to_string();

        let mut wallet_instance = Wallet::init(&path, &rpc_config, mnemonic_seedphrase, passphrase)
            .expect("wallet instance error");

        let fee_rate = 100_000;
        let send_amount = SendAmount::Amount(Amount::from_sat(1000));
        let destination = Destination::Wallet;
        let coins_to_spend = vec![
            CoinToSpend::LongForm(OutPoint {
                txid: Txid::from_str(
                    "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                )
                .unwrap(),
                vout: 0,
            }),
            CoinToSpend::ShortForm {
                prefix: "123abc".to_string(),
                suffix: "def456".to_string(),
                vout: 0,
            },
        ];

        let result =
            wallet_instance.create_direct_send(fee_rate, send_amount, destination, &coins_to_spend);

        assert!(result.is_ok());
    }
}
