#![cfg(feature = "integration-test")]
use bitcoin::{Amount, OutPoint};
use bitcoind::bitcoincore_rpc::{self, RawTx};
use coinswap::{
    
    maker::{start_maker_server, MakerBehavior},
    taker::SwapParams,
    test_framework::*,
    wallet::{Destination,CoinToSpend,SendAmount,UTXOSpendInfo}      

};

use bitcoind::bitcoincore_rpc::RpcApi;
use log::{info, warn};
use std::{thread, time::Duration};




/// This test describes spending from a settled swapcoin.
#[tokio::test]
async fn test_spending_from_settled_swapcoin() {
    // ---- Setup ----

    // 1 Makers with Normal behavior.
    let makers_config_map = [(6102, MakerBehavior::Normal)];

    // Initiate test framework, Maker and a Taker with default behavior.
    let (test_framework, taker, makers) =
        TestFramework::init(None, makers_config_map.into(), None).await;

    warn!("Running Test: Spending from Settled Swapcoin");

    // ---- Standard Coinswap Procedure ----
    info!("Initiating Takers...");
    // Fund the Taker and Makers with 3 utxos of 0.05 btc each.
    for _ in 0..3 {
        let taker_address = taker
            .write()
            .unwrap()
            .get_wallet_mut()
            .get_next_external_address()
            .unwrap();
        test_framework.send_to_address(&taker_address, Amount::from_btc(0.05).unwrap());
        makers.iter().for_each(|maker| {
            let maker_addrs = maker
                .get_wallet()
                .write()
                .unwrap()
                .get_next_external_address()
                .unwrap();
            test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.05).unwrap());
        })
    }


    // ---- Start Servers and attempt Swap ----

    info!("Initiating Maker...");
    // Start the Maker server threads
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_maker_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Start swap
    thread::sleep(Duration::from_secs(20)); // Take a delay because Makers take time to fully setup.
    let swap_params = SwapParams {
        send_amount: 500000,
        maker_count: 2,
        tx_count: 3,
        required_confirms: 1,
        fee_rate: 1000,
    };

    info!("Initiating coinswap protocol");
    // Spawn a Taker coinswap thread.
    let taker_clone = taker.clone();
    let taker_thread = thread::spawn(move || {
        taker_clone
            .write()
            .unwrap()
            .send_coinswap(swap_params)
            .unwrap();
    });

    // Wait for Taker swap thread to conclude.
    taker_thread.join().unwrap();

    // Wait for Maker threads to conclude.
    makers.iter().for_each(|maker| maker.shutdown().unwrap());
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    info!("All coinswaps processed successfully. Transaction complete.");

   //Calculate original balance for taker after coinswap
   let org_taker_balance = taker
   .read()
   .unwrap()
   .get_wallet()
   .balance(false, false)
   .unwrap();

    

    // Step 1: Get swapcoin utxos in the taker wallet
    let unspent_utxos = taker
        .read()
        .unwrap()
        .get_wallet()
        .list_unspent_from_wallet(false, false)
        .unwrap();

  
    // Find the first entry with UTXOSpendInfo::SwapCoin
    if let Some((utxo_entry, spend_info)) = unspent_utxos
    .iter()
    .find(|(_, spend_info)| matches!(spend_info, UTXOSpendInfo::SwapCoin{..}))
{
{
    // Access the fields of the OutPoint directly
    let utxo_outpoint = CoinToSpend::LongForm(OutPoint {
        txid: utxo_entry.txid,
        vout: utxo_entry.vout,
    });

    {
       

        // Create the transaction without broadcasting it
        let mut tx = *taker
            .read()
            .unwrap()
            .get_wallet()
            .create_direct_send(
                1000,                           // fee rate (adjust as needed)
                SendAmount::Amount(Amount::from_sat(50000)), // specify the amount to send
                Destination::Wallet,           // specify the destination (Wallet or Address)
                &[utxo_outpoint], // use the specific swapcoin utxo as input
            )
            .unwrap();

        // Step 3: Signing the tx and wait for confirmation
        taker
            .read()
            .unwrap()
            .get_wallet()
            .sign_transaction(&mut tx, std::iter::once(spend_info.clone()));

        test_framework.generate_1_block(); // Wait for confirmation

        // Step 4: Broadcast the transaction using the existing RPC client
        let raw_tx_hex = tx.raw_hex();
        let client = test_framework.bitcoind.client;

        let tx_id = client.send_raw_transaction(raw_tx_hex);
        println!("Transaction broadcasted successfully. Transaction ID: {:?}", tx_id);

        // Step 5: Assert balance
        let balance_after_spend = taker
        .read()
        .unwrap()
        .get_wallet()
        .balance(false, false)
        .unwrap();
      
            
        let final_balance = org_taker_balance - balance_after_spend;
        assert!(final_balance == Amount::from_btc(0.1499).unwrap_or_else(|_| {
            panic!("Failed to convert BTC to Amount")
        }));
    } 
}
}
}