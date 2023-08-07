//! Various Utility and Helper functions used in both Taker and Maker protocols.

use std::io::ErrorKind;

use bitcoin::{
    secp256k1::{
        rand::{rngs::OsRng, RngCore},
        Secp256k1, SecretKey,
    },
    PublicKey, Script,
};

use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::tcp::{ReadHalf, WriteHalf},
};

use crate::{
    error::TeleportError,
    protocol::{
        contract::derive_maker_pubkey_and_nonce,
        messages::{MakerToTakerMessage, MultisigPrivkey, TakerToMakerMessage},
    },
    wallet::SwapCoin,
};

/// Send message to a Maker.
pub async fn send_message(
    socket_writer: &mut WriteHalf<'_>,
    message: TakerToMakerMessage,
) -> Result<(), TeleportError> {
    log::debug!("==> {:#?}", message);
    let mut result_bytes = serde_json::to_vec(&message).map_err(|e| std::io::Error::from(e))?;
    result_bytes.push(b'\n');
    socket_writer.write_all(&result_bytes).await?;
    Ok(())
}

/// Read a Maker Message
pub async fn read_message(
    reader: &mut BufReader<ReadHalf<'_>>,
) -> Result<MakerToTakerMessage, TeleportError> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(TeleportError::Network(Box::new(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "EOF",
        ))));
    }
    let message: MakerToTakerMessage = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(_e) => return Err(TeleportError::Protocol("json parsing error")),
    };
    log::debug!("<== {:#?}", message);
    Ok(message)
}

/// Apply the maker's privatekey to swapcoins, and check it's the correct privkey for corresponding pubkey.
pub fn check_and_apply_maker_private_keys<S: SwapCoin>(
    swapcoins: &mut Vec<S>,
    swapcoin_private_keys: &[MultisigPrivkey],
) -> Result<(), TeleportError> {
    for (swapcoin, swapcoin_private_key) in swapcoins.iter_mut().zip(swapcoin_private_keys.iter()) {
        swapcoin
            .apply_privkey(swapcoin_private_key.key)
            .map_err(|_| TeleportError::Protocol("wrong privkey"))?;
    }
    Ok(())
}

/// Generate The Maker's Multisig and HashLock keys and respective nonce values.
/// Nonce values are random integers and resulting Pubkeys are derived by tweaking the
/// Make's advertised Pubkey with these two nonces.
pub fn generate_maker_keys(
    tweakable_point: &PublicKey,
    count: u32,
) -> (
    Vec<PublicKey>,
    Vec<SecretKey>,
    Vec<PublicKey>,
    Vec<SecretKey>,
) {
    let (multisig_pubkeys, multisig_nonces): (Vec<_>, Vec<_>) = (0..count)
        .map(|_| derive_maker_pubkey_and_nonce(*tweakable_point).unwrap())
        .unzip();
    let (hashlock_pubkeys, hashlock_nonces): (Vec<_>, Vec<_>) = (0..count)
        .map(|_| derive_maker_pubkey_and_nonce(*tweakable_point).unwrap())
        .unzip();
    (
        multisig_pubkeys,
        multisig_nonces,
        hashlock_pubkeys,
        hashlock_nonces,
    )
}

// /// Performs a handshake with a Maker and returns and Reader and Writer halves.
// pub async fn handshake_maker<'a>(
//     socket: &'a mut TcpStream,
//     maker_address: &MakerAddress,
// ) -> Result<(BufReader<ReadHalf<'a>>, WriteHalf<'a>), TeleportError> {
//     let socket = match maker_address {
//         MakerAddress::Clearnet { address: _ } => socket,
//         MakerAddress::Tor { address } => Socks5Stream::connect_with_socket(socket, address.clone())
//             .await?
//             .into_inner(),
//     };
//     let (reader, mut socket_writer) = socket.split();
//     let mut socket_reader = BufReader::new(reader);
//     send_message(
//         &mut socket_writer,
//         TakerToMakerMessage::TakerHello(TakerHello {
//             protocol_version_min: 0,
//             protocol_version_max: 0,
//         }),
//     )
//     .await?;
//     let makerhello =
//         if let MakerToTakerMessage::MakerHello(m) = read_message(&mut socket_reader).await? {
//             m
//         } else {
//             return Err(TeleportError::Protocol("expected method makerhello"));
//         };
//     log::debug!("{:#?}", makerhello);
//     Ok((socket_reader, socket_writer))
// }

// /// Request signatures for sender side of the hop. Attempt once.
// pub(crate) async fn req_sigs_for_sender_once<S: SwapCoin>(
//     maker_address: &MakerAddress,
//     outgoing_swapcoins: &[S],
//     maker_multisig_nonces: &[SecretKey],
//     maker_hashlock_nonces: &[SecretKey],
//     locktime: u16,
// ) -> Result<ContractSigsForSender, TeleportError> {
//     log::info!("Connecting to {}", maker_address);
//     let mut socket = TcpStream::connect(maker_address.get_tcpstream_address()).await?;
//     let (mut socket_reader, mut socket_writer) =
//         handshake_maker(&mut socket, maker_address).await?;
//     log::info!("===> Sending SignSendersContractTx to {}", maker_address);
//     send_message(
//         &mut socket_writer,
//         TakerToMakerMessage::ReqContractSigsForSender(ReqContractSigsForSender {
//             txs_info: izip!(
//                 maker_multisig_nonces.iter(),
//                 maker_hashlock_nonces.iter(),
//                 outgoing_swapcoins.iter()
//             )
//             .map(
//                 |(&multisig_key_nonce, &hashlock_key_nonce, outgoing_swapcoin)| {
//                     ContractTxInfoForSender {
//                         multisig_key_nonce,
//                         hashlock_key_nonce,
//                         timelock_pubkey: outgoing_swapcoin.get_timelock_pubkey(),
//                         senders_contract_tx: outgoing_swapcoin.get_contract_tx(),
//                         multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
//                         funding_input_value: outgoing_swapcoin.get_funding_amount(),
//                     }
//                 },
//             )
//             .collect::<Vec<ContractTxInfoForSender>>(),
//             hashvalue: outgoing_swapcoins[0].get_hashvalue(),
//             locktime,
//         }),
//     )
//     .await?;
//     let maker_senders_contract_sig = if let MakerToTakerMessage::RespContractSigsForSender(m) =
//         read_message(&mut socket_reader).await?
//     {
//         m
//     } else {
//         return Err(TeleportError::Protocol(
//             "expected method senderscontractsig",
//         ));
//     };
//     if maker_senders_contract_sig.sigs.len() != outgoing_swapcoins.len() {
//         return Err(TeleportError::Protocol(
//             "wrong number of signatures from maker",
//         ));
//     }
//     if maker_senders_contract_sig
//         .sigs
//         .iter()
//         .zip(outgoing_swapcoins.iter())
//         .any(|(sig, outgoing_swapcoin)| !outgoing_swapcoin.verify_contract_tx_sender_sig(&sig))
//     {
//         return Err(TeleportError::Protocol("invalid signature from maker"));
//     }
//     log::info!("<=== Received SendersContractSig from {}", maker_address);
//     Ok(maker_senders_contract_sig)
// }

// /// Request signatures for receiver side of the hop. Attempt once.
// pub(crate) async fn req_sigs_for_recvr_once<S: SwapCoin>(
//     maker_address: &MakerAddress,
//     incoming_swapcoins: &[S],
//     receivers_contract_txes: &[Transaction],
// ) -> Result<ContractSigsForRecvr, TeleportError> {
//     log::info!("Connecting to {}", maker_address);
//     let mut socket = TcpStream::connect(maker_address.get_tcpstream_address()).await?;
//     let (mut socket_reader, mut socket_writer) =
//         handshake_maker(&mut socket, maker_address).await?;
//     send_message(
//         &mut socket_writer,
//         TakerToMakerMessage::ReqContractSigsForRecvr(ReqContractSigsForRecvr {
//             txs: incoming_swapcoins
//                 .iter()
//                 .zip(receivers_contract_txes.iter())
//                 .map(|(swapcoin, receivers_contract_tx)| ContractTxInfoForRecvr {
//                     multisig_redeemscript: swapcoin.get_multisig_redeemscript(),
//                     contract_tx: receivers_contract_tx.clone(),
//                 })
//                 .collect::<Vec<ContractTxInfoForRecvr>>(),
//         }),
//     )
//     .await?;
//     let maker_receiver_contract_sig = if let MakerToTakerMessage::RespContractSigsForRecvr(m) =
//         read_message(&mut socket_reader).await?
//     {
//         m
//     } else {
//         return Err(TeleportError::Protocol(
//             "expected method receiverscontractsig",
//         ));
//     };
//     if maker_receiver_contract_sig.sigs.len() != incoming_swapcoins.len() {
//         return Err(TeleportError::Protocol(
//             "wrong number of signatures from maker",
//         ));
//     }
//     if maker_receiver_contract_sig
//         .sigs
//         .iter()
//         .zip(incoming_swapcoins.iter())
//         .any(|(sig, swapcoin)| !swapcoin.verify_contract_tx_receiver_sig(&sig))
//     {
//         return Err(TeleportError::Protocol("invalid signature from maker"));
//     }

//     log::info!("<=== Received ReceiversContractSig from {}", maker_address);
//     Ok(maker_receiver_contract_sig)
// }

// /// [Internal] Send a Proof funding to the maker and init next hop.
// pub(crate) async fn send_proof_of_funding_and_init_next_hop(
//     socket_reader: &mut BufReader<ReadHalf<'_>>,
//     socket_writer: &mut WriteHalf<'_>,
//     this_maker: &OfferAndAddress,
//     funding_tx_infos: &Vec<FundingTxInfo>,
//     next_peer_multisig_pubkeys: &Vec<PublicKey>,
//     next_peer_hashlock_pubkeys: &Vec<PublicKey>,
//     next_maker_refund_locktime: u16,
//     next_maker_fee_rate: u64,
//     this_maker_contract_txes: &Vec<Transaction>,
//     hashvalue: Hash160,
// ) -> Result<(ContractSigsAsRecvrAndSender, Vec<Script>), TeleportError> {
//     send_message(
//         socket_writer,
//         TakerToMakerMessage::RespProofOfFunding(ProofOfFunding {
//             confirmed_funding_txes: funding_tx_infos.clone(),
//             next_coinswap_info: next_peer_multisig_pubkeys
//                 .iter()
//                 .zip(next_peer_hashlock_pubkeys.iter())
//                 .map(
//                     |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextHopInfo {
//                         next_multisig_pubkey: next_coinswap_multisig_pubkey,
//                         next_hashlock_pubkey,
//                     },
//                 )
//                 .collect::<Vec<NextHopInfo>>(),
//             next_locktime: next_maker_refund_locktime,
//             next_fee_rate: next_maker_fee_rate,
//         }),
//     )
//     .await?;
//     let maker_sign_sender_and_receiver_contracts =
//         if let MakerToTakerMessage::ReqContractSigsAsRecvrAndSender(m) =
//             read_message(socket_reader).await?
//         {
//             m
//         } else {
//             return Err(TeleportError::Protocol(
//                 "expected method signsendersandreceiverscontracttxes",
//             ));
//         };
//     if maker_sign_sender_and_receiver_contracts
//         .receivers_contract_txs
//         .len()
//         != funding_tx_infos.len()
//     {
//         return Err(TeleportError::Protocol(
//             "wrong number of receivers contracts tx from maker",
//         ));
//     }
//     if maker_sign_sender_and_receiver_contracts
//         .senders_contract_txs_info
//         .len()
//         != next_peer_multisig_pubkeys.len()
//     {
//         return Err(TeleportError::Protocol(
//             "wrong number of senders contract txes from maker",
//         ));
//     }

//     let funding_tx_values = funding_tx_infos
//         .iter()
//         .map(|funding_info| {
//             find_funding_output(
//                 &funding_info.funding_tx,
//                 &funding_info.multisig_redeemscript,
//             )
//             .ok_or(TeleportError::Protocol(
//                 "multisig redeemscript not found in funding tx",
//             ))
//             .map(|txout| txout.1.value)
//         })
//         .collect::<Result<Vec<u64>, TeleportError>>()?;

//     let this_amount = funding_tx_values.iter().sum::<u64>();

//     let next_amount = maker_sign_sender_and_receiver_contracts
//         .senders_contract_txs_info
//         .iter()
//         .map(|i| i.funding_amount)
//         .sum::<u64>();
//     let coinswap_fees = calculate_coinswap_fee(
//         this_maker.offer.absolute_fee_sat,
//         this_maker.offer.amount_relative_fee_ppb,
//         this_maker.offer.time_relative_fee_ppb,
//         this_amount,
//         1, //time_in_blocks just 1 for now
//     );
//     let miner_fees_paid_by_taker = MAKER_FUNDING_TX_VBYTE_SIZE
//         * next_maker_fee_rate
//         * (next_peer_multisig_pubkeys.len() as u64)
//         / 1000;
//     let calculated_next_amount = this_amount - coinswap_fees - miner_fees_paid_by_taker;
//     if calculated_next_amount != next_amount {
//         return Err(TeleportError::Protocol("next_amount incorrect"));
//     }
//     log::info!(
//         "this_amount={} coinswap_fees={} miner_fees_paid_by_taker={} next_amount={}",
//         this_amount,
//         coinswap_fees,
//         miner_fees_paid_by_taker,
//         next_amount
//     );

//     for ((receivers_contract_tx, contract_tx), contract_redeemscript) in
//         maker_sign_sender_and_receiver_contracts
//             .receivers_contract_txs
//             .iter()
//             .zip(this_maker_contract_txes.iter())
//             .zip(funding_tx_infos.iter().map(|fi| &fi.contract_redeemscript))
//     {
//         validate_contract_tx(
//             &receivers_contract_tx,
//             Some(&contract_tx.input[0].previous_output),
//             contract_redeemscript,
//         )?;
//     }
//     let next_swap_contract_redeemscripts = next_peer_hashlock_pubkeys
//         .iter()
//         .zip(
//             maker_sign_sender_and_receiver_contracts
//                 .senders_contract_txs_info
//                 .iter(),
//         )
//         .map(|(hashlock_pubkey, senders_contract_tx_info)| {
//             create_contract_redeemscript(
//                 hashlock_pubkey,
//                 &senders_contract_tx_info.timelock_pubkey,
//                 hashvalue,
//                 next_maker_refund_locktime,
//             )
//         })
//         .collect::<Vec<Script>>();
//     Ok((
//         maker_sign_sender_and_receiver_contracts,
//         next_swap_contract_redeemscripts,
//     ))
// }

// /// Send hash preimage via the writer and read the response.
// pub(crate) async fn send_hash_preimage_and_get_private_keys(
//     socket_reader: &mut BufReader<ReadHalf<'_>>,
//     socket_writer: &mut WriteHalf<'_>,
//     senders_multisig_redeemscripts: &Vec<Script>,
//     receivers_multisig_redeemscripts: &Vec<Script>,
//     preimage: &Preimage,
// ) -> Result<PrivKeyHandover, TeleportError> {
//     let receivers_multisig_redeemscripts_len = receivers_multisig_redeemscripts.len();
//     send_message(
//         socket_writer,
//         TakerToMakerMessage::RespHashPreimage(HashPreimage {
//             senders_multisig_redeemscripts: senders_multisig_redeemscripts.to_vec(),
//             receivers_multisig_redeemscripts: receivers_multisig_redeemscripts.to_vec(),
//             preimage: *preimage,
//         }),
//     )
//     .await?;
//     let maker_private_key_handover =
//         if let MakerToTakerMessage::RespPrivKeyHandover(m) = read_message(socket_reader).await? {
//             m
//         } else {
//             return Err(TeleportError::Protocol(
//                 "expected method privatekeyhandover",
//             ));
//         };
//     if maker_private_key_handover.multisig_privkeys.len() != receivers_multisig_redeemscripts_len {
//         return Err(TeleportError::Protocol(
//             "wrong number of private keys from maker",
//         ));
//     }
//     Ok(maker_private_key_handover)
// }

// pub fn apply_two_signatures_to_2of2_multisig_spend(
//     key1: &PublicKey,
//     key2: &PublicKey,
//     sig1: &Signature,
//     sig2: &Signature,
//     input: &mut TxIn,
//     redeemscript: &Script,
// ) {
//     let (sig_first, sig_second) = if key1.key.serialize()[..] < key2.key.serialize()[..] {
//         (sig1, sig2)
//     } else {
//         (sig2, sig1)
//     };

//     input.witness.push(Vec::new()); //first is multisig dummy
//     input.witness.push(sig_first.serialize_der().to_vec());
//     input.witness.push(sig_second.serialize_der().to_vec());
//     input.witness[1].push(SigHashType::All as u8);
//     input.witness[2].push(SigHashType::All as u8);
//     input.witness.push(redeemscript.to_bytes());
// }

pub fn convert_json_rpc_bitcoin_to_satoshis(amount: &Value) -> u64 {
    //to avoid floating point arithmetic, convert the bitcoin amount to
    //string with 8 decimal places, then remove the decimal point to
    //obtain the value in satoshi
    //this is necessary because the json rpc represents bitcoin values
    //as floats :(
    format!("{:.8}", amount.as_f64().unwrap())
        .replace(".", "")
        .parse::<u64>()
        .unwrap()
}

// returns None if not a hd descriptor (but possibly a swapcoin (multisig) descriptor instead)
pub fn get_hd_path_from_descriptor<'a>(descriptor: &'a str) -> Option<(&'a str, u32, i32)> {
    //e.g
    //"desc": "wpkh([a945b5ca/1/1]029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9",
    let open = descriptor.find('[');
    let close = descriptor.find(']');
    if open.is_none() || close.is_none() {
        //unexpected, so printing it to stdout
        println!("unknown descriptor = {}", descriptor);
        return None;
    }
    let path = &descriptor[open.unwrap() + 1..close.unwrap()];
    let path_chunks: Vec<&str> = path.split('/').collect();
    if path_chunks.len() != 3 {
        return None;
        //unexpected descriptor = wsh(multi(2,[f67b69a3]0245ddf535f08a04fd86d794b76f8e3949f27f7ae039b641bf277c6a4552b4c387,[dbcd3c6e]030f781e9d2a6d3a823cee56be2d062ed4269f5a6294b20cb8817eb540c641d9a2))#8f70vn2q
    }
    let addr_type = path_chunks[1].parse::<u32>();
    if addr_type.is_err() {
        log::debug!(target: "wallet", "unexpected address_type = {}", path);
        return None;
    }
    let index = path_chunks[2].parse::<i32>();
    if index.is_err() {
        return None;
    }
    Some((path_chunks[0], addr_type.unwrap(), index.unwrap()))
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let mut privkey = [0u8; 32];
    let mut rng = OsRng::new().expect("Panic while creating OsRng");
    rng.fill_bytes(&mut privkey);
    let secp = Secp256k1::new();
    let privkey = SecretKey::from_slice(&privkey).unwrap();
    let pubkey = PublicKey {
        compressed: true,
        key: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &privkey),
    };
    (pubkey, privkey)
}

// pub fn create_multisig_redeemscript(key1: &PublicKey, key2: &PublicKey) -> Script {
//     let builder = Builder::new().push_opcode(all::OP_PUSHNUM_2);
//     if key1.key.serialize()[..] < key2.key.serialize()[..] {
//         builder.push_key(key1).push_key(key2)
//     } else {
//         builder.push_key(key2).push_key(key1)
//     }
//     .push_opcode(all::OP_PUSHNUM_2)
//     .push_opcode(all::OP_CHECKMULTISIG)
//     .into_script()
// }

// pub fn derive_maker_pubkey_and_nonce(
//     tweakable_point: PublicKey,
// ) -> Result<(PublicKey, SecretKey), secpError> {
//     let mut nonce_bytes = [0u8; 32];
//     let mut rng = OsRng::new().unwrap();
//     rng.fill_bytes(&mut nonce_bytes);
//     let nonce = SecretKey::from_slice(&nonce_bytes)?;
//     let maker_pubkey = calculate_maker_pubkey_from_nonce(tweakable_point, nonce)?;

//     Ok((maker_pubkey, nonce))
// }

// pub fn calculate_maker_pubkey_from_nonce(
//     tweakable_point: PublicKey,
//     nonce: SecretKey,
// ) -> Result<PublicKey, secpError> {
//     let secp = Secp256k1::new();

//     let nonce_point = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &nonce);
//     Ok(PublicKey {
//         compressed: true,
//         key: tweakable_point.key.combine(&nonce_point)?,
//     })
// }

/// Convert a redeemscript into p2wsh scriptpubkey.
pub fn redeemscript_to_scriptpubkey(redeemscript: &Script) -> Script {
    //p2wsh address
    Script::new_witness_program(
        bitcoin::bech32::u5::try_from_u8(0).unwrap(),
        &redeemscript.wscript_hash().to_vec(),
    )
}

// pub fn calculate_coinswap_fee(
//     absolute_fee_sat: u64,
//     amount_relative_fee_ppb: u64,
//     time_relative_fee_ppb: u64,
//     total_funding_amount: u64,
//     time_in_blocks: u64,
// ) -> u64 {
//     absolute_fee_sat
//         + (total_funding_amount * amount_relative_fee_ppb / 1_000_000_000)
//         + (time_in_blocks * time_relative_fee_ppb / 1_000_000_000)
// }

// pub fn find_funding_output<'a>(
//     funding_tx: &'a Transaction,
//     multisig_redeemscript: &Script,
// ) -> Option<(u32, &'a TxOut)> {
//     let multisig_spk = redeemscript_to_scriptpubkey(&multisig_redeemscript);
//     funding_tx
//         .output
//         .iter()
//         .enumerate()
//         .map(|(i, o)| (i as u32, o))
//         .find(|(_i, o)| o.script_pubkey == multisig_spk)
// }
