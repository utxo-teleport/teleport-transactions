mod direct_send;
mod error;
pub mod fidelity;
mod funding;
mod rpc;
mod storage;
mod swapcoin;
mod api;

pub use direct_send::{CoinToSpend, Destination, SendAmount};
pub use error::WalletError;
pub use rpc::RPCConfig;
pub use storage::WalletStore;
pub use swapcoin::{
    IncomingSwapCoin, OutgoingSwapCoin, SwapCoin, WalletSwapCoin, WatchOnlySwapCoin,
};
pub use api::{DisplayAddressType, UTXOSpendInfo, Wallet};