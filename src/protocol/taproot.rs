#[allow(dead_code)] 
use std::rand::{thread_rng, RngCore};
use bitcoin::Script;
use secp256k1_zkp::{ffi::{MusigSecNonce, PublicKey}, Keypair, Message, MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigSession, MusigSessionId, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

/// Constant representing the virtual byte size of a funding transaction.
pub const FUNDING_TX_VBYTE_SIZE: u64 = 372;
const MIN_HASHV_LEN: usize = 32;

// Used in read_pubkeys_from_multisig_redeemscript() function.
const PUBKEY_LENGTH_1: usize = 33;
const PUBKEY_LENGTH_2: usize = 33;

struct NonceKeypair {
    pub_nonce: MusigPubNonce,
    priv_nonce: MusigSecNonce,
}
struct PartialSign(
    SecretKey,
    NonceKeypair,
    MusigAggNonce,
);

//call  MusigKeyAggCache::agg_pub() to get pubkey
pub fn musig_pubkey_aggregated(pub_key1:PublicKey, pub_key2:PublicKey)-> MusigKeyAggCache {
    let secp = Secp256k1::new();
    let mut arr: Vec<PublicKey>;
    arr.push[pub_key1];
    arr.push[pub_key2];
    arr.sort();

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[arr[0].into(), arr[1].into()]);
    return key_agg_cache;
}

pub fn partial_signature(
    sec_key1: SecretKey,
    sec_key2: SecretKey, 
    )->(){
    
    let secp = Secp256k1::new();
    let pub_key1 = secp256k1_zkp::PublicKey::from_secret_key(&secp, &sec_key1);
    let pub_key2 = secp256k1_zkp::PublicKey::from_secret_key(&secp, &sec_key2);

    let key_agg_cache = musig_pubkey_aggregated(pub_key1, pub_key2);

    let session_id1 = MusigSessionId::new(&mut thread_rng());

    let adapt_pub = PublicKey::from_secret_key(&secp, &sec_key);
    let adapt_sec = Tweak::from_slice(adapt_sec.as_ref()).unwrap();
    
    let session = MusigSession::with_adaptor(
        &secp,
        &key_agg_cache,
        aggnonce,
        msg,
        adapt_pub,
    );

    let partial_sig1 = session.partial_sign(
        &secp,
        sec_nonce1,
        &Keypair::from_secret_key(&secp, &sk1),
        &key_agg_cache,
    ).unwrap();
}

pub fn musig_signature_aggregated()->(){
    
}





pub fn hashlock() -> () {
    todo!()
}

pub fn timelock() -> () {
    todo!()
}

pub fn taproot_script_constructor() -> () {
    todo!(
        v1 script of 33 byte
        taptweak musig_signature_aggregated() and hashscript and timelock
    ) 

}

pub fn taproot_key_spend_path ()->() {
    todo!(
        musig_signature_aggregated() 1 
        musig_signature_aggregated() 2
        witness v1 with 65 byte schnoor signature 

    )
}

pub fn taproot_hashlock_spend_path ()->() {
    todo!()
}


pub fn taproot_timelock_spend_path ()->() {
    todo!()
}