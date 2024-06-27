use bitcoin::{key::XOnlyPublicKey, taproot::{TaprootBuilder, TaprootSpendInfo}, ScriptBuf};
//need to handle the case where the pubkeys are returned and not secNonce   

pub fn nonce_gen(
    pub_key1:secp256k1_zkp::PublicKey,
    pub_key2:secp256k1_zkp::PublicKey,
    msg : secp256k1_zkp::Message
)->(secp256k1_zkp::MusigSecNonce, secp256k1_zkp::MusigPubNonce) {
    let secp = secp256k1_zkp::Secp256k1::new();
    let key_agg_cache = secp256k1_zkp::MusigKeyAggCache::new(
        &secp, 
        &[pub_key1, pub_key2]);
    
    // The session id must be sampled at random. Read documentation for more details.
    let session_id1 = secp256k1_zkp::MusigSessionId::assume_unique_per_nonce_gen(
        bitcoin::secp256k1::rand::random()
    );
    let (sec_nonce, pub_nonce):(
        secp256k1_zkp::MusigSecNonce, 
        secp256k1_zkp::MusigPubNonce) 
        = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, None)
        .expect("non zero session id");
    return (sec_nonce, pub_nonce);
}

//only should be called when we have to create a partial signature
pub fn partial_signature_gen(
    sec_key: secp256k1_zkp::SecretKey,
    sec_nonce: secp256k1_zkp::MusigSecNonce,
    pub_nonce1: secp256k1_zkp::MusigPubNonce,
    pub_nonce2: secp256k1_zkp::MusigPubNonce,
    msg:secp256k1_zkp::Message, 
    pub_key1: secp256k1_zkp::PublicKey,
    pub_key2: secp256k1_zkp::PublicKey,
)-> secp256k1_zkp::MusigPartialSignature{
    let secp = secp256k1_zkp::Secp256k1::new();
    let keypair:secp256k1_zkp::Keypair = secp256k1_zkp::Keypair::from_secret_key(&secp, &sec_key);
    let mut arr_pub: Vec<secp256k1_zkp::PublicKey> = Vec::new();
        arr_pub.push(pub_key1);
        arr_pub.push(pub_key2);
        arr_pub.sort();
    let key_agg_cache = secp256k1_zkp::MusigKeyAggCache::new(&secp, &[arr_pub[0].into(), arr_pub[1].into()]);

    // let mut arr_nonce: Vec<secp256k1_zkp::MusigPubNonce> = Vec::new();
    //     arr_nonce.push(pub_nonce1);
    //     arr_nonce.push(pub_nonce2);
    //     arr_nonce.sort();
    let aggnonce = secp256k1_zkp::MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    let session = secp256k1_zkp::MusigSession::new(
        &secp,
        &key_agg_cache,
        aggnonce,
        msg,
    );
    let partial_sig:secp256k1_zkp::MusigPartialSignature = session.partial_sign(
        &secp,
        sec_nonce,
        &keypair,
        &key_agg_cache,
    ).unwrap();   
    
    return partial_sig; 
}

//only should be called when we have to create a complete signature
pub fn musig_signature(
    partial_sig2: secp256k1_zkp::MusigPartialSignature, 
    sec_key: secp256k1_zkp::SecretKey,
    sec_nonce: secp256k1_zkp::MusigSecNonce,
    pub_nonce1: secp256k1_zkp::MusigPubNonce,
    pub_nonce2: secp256k1_zkp::MusigPubNonce,
    msg:secp256k1_zkp::Message, 
    pub_key2: secp256k1_zkp::PublicKey,
    )-> secp256k1_zkp::schnorr::Signature{
    let secp = secp256k1_zkp::Secp256k1::new();
    let keypair = secp256k1_zkp::Keypair::from_secret_key(&secp, &sec_key);
    let mut arr: Vec<secp256k1_zkp::PublicKey> = Vec::new();
        arr.push(keypair.public_key());
        arr.push(pub_key2);
        arr.sort();
    let key_agg_cache = secp256k1_zkp::MusigKeyAggCache::new(&secp, &[arr[0].into(), arr[1].into()]);
    let aggnonce = secp256k1_zkp::MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    let session = secp256k1_zkp::MusigSession::new(
        &secp,
        &key_agg_cache,
        aggnonce,
        msg,
    );
    let keypair = secp256k1_zkp::Keypair::from_secret_key(&secp, &sec_key);
    let partial_sig1:secp256k1_zkp::MusigPartialSignature = session.partial_sign(
        &secp,
        sec_nonce,
        &keypair,
        &key_agg_cache,
    ).unwrap();   

    let schnorr_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
    return schnorr_sig;
}

// pub fn hashlock() -> () {
//     todo!()
// }

// pub fn timelock() -> () {
//     todo!()
// }

pub fn taproot_script_constructor(
    script1: ScriptBuf,
    script2: ScriptBuf,
    key: XOnlyPublicKey,
) -> TaprootSpendInfo {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let script = TaprootBuilder::new()
        .add_leaf(1u8, script1).expect("script1")
        .add_leaf(1u8, script2).expect("script2")
        .finalize(&secp, key)
        .unwrap();
    return script;
}

pub fn taproot_key_spend_path ()->() {
    todo!()
}

pub fn taproot_hashlock_spend_path ()->() {
    todo!()
}

pub fn taproot_timelock_spend_path ()->() {
    todo!()
}