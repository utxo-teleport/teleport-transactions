use std::path::PathBuf;

use crate::utill::{parse_field, parse_toml};

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
            port: 6102,
            heart_beat_interval_secs: 3,
            rpc_ping_interval_secs: 60,
            watchtower_ping_interval_secs: 300,
            directory_servers_refresh_interval_secs: 60 * 60 * 12, //12 Hours
            idle_connection_timeout: 300,
            onion_addrs: "myhiddenserviceaddress.onion:6102".to_string(),
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
    /// new a default configuration with given port and address
    pub fn init(port: u16, onion_addrs: String) -> Self {
        Self {
            port,
            onion_addrs,
            ..MakerConfig::default()
        }
    }
    pub fn new(file_path: Option<&PathBuf>) -> Self {
        let default_config = Self::default();
        let default_path = PathBuf::from("maker.toml");
        let path = file_path.unwrap_or(&default_path);

        // Check if the file exists
        if !path.exists() {
            eprintln!("Config file not found: {:?}", path);
            return default_config;
        }

        // Attempt to parse the TOML file
        let sections = match parse_toml(path) {
            Ok(sections) => sections,
            Err(err) => {
                eprintln!("Error parsing config file: {:?}", err);
                return default_config;
            }
        };

        let maker_config_section = match sections.get("maker_config") {
            Some(config) => config,
            None => {
                eprintln!("'maker_config' section not found in config file");
                return default_config;
            }
        };

        MakerConfig {
            port: parse_field(
                "port",
                maker_config_section.get("port"),
                default_config.port,
            ),
            heart_beat_interval_secs: parse_field(
                "heart_beat_interval_secs",
                maker_config_section.get("heart_beat_interval_secs"),
                default_config.heart_beat_interval_secs,
            ),
            rpc_ping_interval_secs: parse_field(
                "rpc_ping_interval_secs",
                maker_config_section.get("rpc_ping_interval_secs"),
                default_config.rpc_ping_interval_secs,
            ),
            watchtower_ping_interval_secs: parse_field(
                "watchtower_ping_interval_secs",
                maker_config_section.get("watchtower_ping_interval_secs"),
                default_config.watchtower_ping_interval_secs,
            ),
            directory_servers_refresh_interval_secs: parse_field(
                "directory_servers_refresh_interval_secs",
                maker_config_section.get("directory_servers_refresh_interval_secs"),
                default_config.directory_servers_refresh_interval_secs,
            ),
            idle_connection_timeout: parse_field(
                "idle_connection_timeout",
                maker_config_section.get("idle_connection_timeout"),
                default_config.idle_connection_timeout,
            ),
            onion_addrs: maker_config_section
                .get("onion_addrs")
                .map(|s| s.to_string())
                .unwrap_or(default_config.onion_addrs),
            absolute_fee_sats: parse_field(
                "absolute_fee_sats",
                maker_config_section.get("absolute_fee_sats"),
                default_config.absolute_fee_sats,
            ),
            amount_relative_fee_ppb: parse_field(
                "amount_relative_fee_ppb",
                maker_config_section.get("amount_relative_fee_ppb"),
                default_config.amount_relative_fee_ppb,
            ),
            time_relative_fee_ppb: parse_field(
                "time_relative_fee_ppb",
                maker_config_section.get("time_relative_fee_ppb"),
                default_config.time_relative_fee_ppb,
            ),
            required_confirms: parse_field(
                "required_confirms",
                maker_config_section.get("required_confirms"),
                default_config.required_confirms,
            ),
            min_contract_reaction_time: parse_field(
                "min_contract_reaction_time",
                maker_config_section.get("min_contract_reaction_time"),
                default_config.min_contract_reaction_time,
            ),
            min_size: parse_field(
                "min_size",
                maker_config_section.get("min_size"),
                default_config.min_size,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    fn create_temp_config(contents: &str, file_name: &str) -> PathBuf {
        let file_path = PathBuf::from(file_name);
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{}", contents).unwrap();
        file_path
    }

    fn remove_temp_config(path: &PathBuf) {
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_valid_config() {
        let contents = r#"
            [maker_config]
            port = 6102
            heart_beat_interval_secs = 3
            rpc_ping_interval_secs = 60
            watchtower_ping_interval_secs = 300
            directory_servers_refresh_interval_secs = 43200
            idle_connection_timeout = 300
            absolute_fee_sats = 1000
            amount_relative_fee_ppb = 10000000
            time_relative_fee_ppb = 100000
            required_confirms = 1
            min_contract_reaction_time = 48
            min_size = 10000
        "#;
        let config_path = create_temp_config(contents, "valid_maker_config.toml");
        let config = MakerConfig::new(Some(&config_path));
        remove_temp_config(&config_path);

        let default_config = MakerConfig::default();
        assert_eq!(config, default_config);
    }

    #[test]
    fn test_missing_fields() {
        let contents = r#"
            [maker_config]
            port = 6103
        "#;
        let config_path = create_temp_config(contents, "missing_fields_maker_config.toml");
        let config = MakerConfig::new(Some(&config_path));
        remove_temp_config(&config_path);

        assert_eq!(config.port, 6103);
        assert_eq!(
            MakerConfig {
                port: 6102,
                ..config
            },
            MakerConfig::default()
        );
    }

    #[test]
    fn test_incorrect_data_type() {
        let contents = r#"
            [maker_config]
            port = "not_a_number"
        "#;
        let config_path = create_temp_config(contents, "incorrect_type_maker_config.toml");
        let config = MakerConfig::new(Some(&config_path));
        remove_temp_config(&config_path);

        assert_eq!(config.port, MakerConfig::default().port);
    }
}
