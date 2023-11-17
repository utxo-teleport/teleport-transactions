use std::path::PathBuf;

use crate::utill::parse_toml;

/// Maker Configuration, controlling various maker behavior.
#[derive(Debug, Clone, PartialEq)]
pub struct MakerConfig {
    /// Listening port
    pub port: u16,
    /// Time interval between connection checks
    pub heart_beat_interval_secs: u64,
    /// Time interval to ping the RPC backend
    pub rpc_ping_interval_secs: u64,
    /// Time interval to ping the watchtower
    pub watchtower_ping_interval_secs: u64,
    /// Time interval ping directory server
    pub directory_servers_refresh_interval_secs: u64,
    /// Time interval to close a connection if no response is received
    pub idle_connection_timeout: u64,
    /// Onion address of the Maker
    pub onion_addrs: String,
    /// Absolute coinswap fee
    pub absolute_fee_sats: u64,
    /// Fee rate per swap amount in ppb.
    pub amount_relative_fee_ppb: u64,
    /// Fee rate for timelocked contract in ppb
    pub time_relative_fee_ppb: u64,
    /// No of confirmation required for funding transaction
    pub required_confirms: u64,
    // Minimum timelock difference between contract transaction of two hops
    pub min_contract_reaction_time: u16,
    /// Minimum coinswap amount size in sats
    pub min_size: u64,
}

impl Default for MakerConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "onion@example".to_string(),
            absolute_fee_sats: 1000,
            amount_relative_fee_ppb: 10_000_000,
            time_relative_fee_ppb: 100_000,
            required_confirms: 1,
            min_contract_reaction_time: 48,
            min_size: 10_000,
        }
    }
}

impl MakerConfig {
    /// Init a default configuration with given port and address
    pub fn init(port: u16, onion_addrs: String, file_path: Option<&PathBuf>) -> Self {
        let sections = if let Some(path) = file_path {
            parse_toml(path)
        } else {
            parse_toml(&PathBuf::from("maker.toml"))
        };

        if sections.is_err() {
            return Self {
                port,
                onion_addrs,
                ..MakerConfig::default()
            };
        }
        let section = sections.unwrap();

        if let None = section.get("maker.toml") {
            return Self {
                port,
                onion_addrs,
                ..MakerConfig::default()
            };
        }

        let maker_config_section = section.get("maker_config").unwrap();

        let maker_keys = vec![
            "absolute_fee_sats",
            "amount_relative_fee_ppb",
            "time_relative_fee_ppb",
            "required_confirms",
            "min_contract_reaction_time",
            "min_size",
            "idle_connection_timeout",
            "watchtower_ping_interval_secs",
            "heart_beat_interval_secs",
            "heart_beat_interval_secs",
            "rpc_ping_interval_secs",
            "directory_servers_refresh_interval_secs",
        ];

        for x in maker_keys.iter() {
            if maker_config_section.contains_key(*x) == false {
                return Self {
                    port,
                    onion_addrs,
                    ..MakerConfig::default()
                };
            }
        }
        MakerConfig {
            port,
            absolute_fee_sats: maker_config_section
                .get("absolute_fee_sats")
                .unwrap()
                .parse()
                .unwrap(),
            amount_relative_fee_ppb: maker_config_section
                .get("amount_relative_fee_ppb")
                .unwrap()
                .parse()
                .unwrap(),
            time_relative_fee_ppb: maker_config_section
                .get("time_relative_fee_ppb")
                .unwrap()
                .parse()
                .unwrap(),
            required_confirms: maker_config_section
                .get("required_confirms")
                .unwrap()
                .parse()
                .unwrap(),
            min_contract_reaction_time: maker_config_section
                .get("min_contract_reaction_time")
                .unwrap()
                .parse()
                .unwrap(),
            min_size: maker_config_section
                .get("min_size")
                .unwrap()
                .parse()
                .unwrap(),
            idle_connection_timeout: maker_config_section
                .get("idle_connection_timeout")
                .unwrap()
                .parse()
                .unwrap(),
            watchtower_ping_interval_secs: maker_config_section
                .get("watchtower_ping_interval_secs")
                .unwrap()
                .parse()
                .unwrap(),
            heart_beat_interval_secs: maker_config_section
                .get("heart_beat_interval_secs")
                .unwrap()
                .parse()
                .unwrap(),
            onion_addrs,
            rpc_ping_interval_secs: maker_config_section
                .get("rpc_ping_interval_secs")
                .unwrap()
                .parse()
                .unwrap(),
            directory_servers_refresh_interval_secs: maker_config_section
                .get("directory_servers_refresh_interval_secs")
                .unwrap()
                .parse()
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::MakerConfig;

    #[test]
    fn test_parsing_toml_maker_all_works() {
        let dummy_maker = MakerConfig {
            port: 3000,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "example.onion".to_string(),
            absolute_fee_sats: 1000,
            amount_relative_fee_ppb: 10_000_000,
            time_relative_fee_ppb: 100_000,
            required_confirms: 1,
            min_contract_reaction_time: 48,
            min_size: 10_000,
        };

        let parsed_maker = MakerConfig::init(
            3000,
            "example.onion".to_string(),
            Some(&PathBuf::from("maker.toml")),
        );
        // Everything works fine
        assert_eq!(dummy_maker, parsed_maker);
    }

    #[test]
    fn test_parsing_toml_maker_file_missing() {
        let dummy_maker = MakerConfig {
            port: 3000,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "example.onion".to_string(),
            absolute_fee_sats: 1000,
            amount_relative_fee_ppb: 10_000_000,
            time_relative_fee_ppb: 100_000,
            required_confirms: 1,
            min_contract_reaction_time: 48,
            min_size: 10_000,
        };

        let parsed_maker = MakerConfig::init(
            3000,
            "example.onion".to_string(),
            Some(&PathBuf::from("make.toml")),
        );
        // Taking the default path, when the file is not present
        assert_eq!(dummy_maker, parsed_maker);
    }

    #[test]
    fn test_parsing_toml_maker_wrong_file() {
        let dummy_maker = MakerConfig {
            port: 3000,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "example.onion".to_string(),
            absolute_fee_sats: 1000,
            amount_relative_fee_ppb: 10_000_000,
            time_relative_fee_ppb: 100_000,
            required_confirms: 1,
            min_contract_reaction_time: 48,
            min_size: 10_000,
        };

        let parsed_maker = MakerConfig::init(
            3000,
            "example.onion".to_string(),
            Some(&PathBuf::from("config.toml")),
        );
        // Taking the default path, when the file is not present
        assert_eq!(dummy_maker, parsed_maker);
    }

    #[test]
    fn test_parsing_toml_maker_faulty_data() {
        let dummy_maker = MakerConfig {
            port: 3000,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "example.onion".to_string(),
            absolute_fee_sats: 1000,
            amount_relative_fee_ppb: 10_000_000,
            time_relative_fee_ppb: 100_000,
            required_confirms: 1,
            min_contract_reaction_time: 48,
            min_size: 10_000,
        };

        let parsed_maker = MakerConfig::init(
            3000,
            "example.onion".to_string(),
            Some(&PathBuf::from("config.toml")),
        );
        // Taking the default path, when the file is not present
        assert_eq!(dummy_maker, parsed_maker);
    }
}
