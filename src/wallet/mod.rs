//! The Coinswap Wallet (unsecured). Used by both the Taker and Maker.

mod bdk_wallet;
mod error;
mod rpc;
mod storage;
mod swapcoin;

use bdk_wallet::*;
use swapcoin::*;

pub use api::{DisplayAddressType, UTXOSpendInfo, Wallet};
pub use direct_send::{CoinToSpend, Destination, SendAmount};
pub use error::WalletError;
pub use fidelity::{FidelityBond, FidelityError};
pub use rpc::RPCConfig;
pub use storage::WalletStore;
pub use swapcoin_structs::{
    IncomingSwapCoin, OutgoingSwapCoin, SwapCoin, WalletSwapCoin, WatchOnlySwapCoin,
};
