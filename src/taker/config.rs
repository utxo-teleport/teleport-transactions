use std::path::PathBuf;

use crate::utill::{parse_field, parse_toml};
/// Various global configurations defining the Taker behavior.
/// TODO: Optionally read this from a config file.
#[derive(Debug, Clone, PartialEq)]
pub struct TakerConfig {
    pub refund_locktime: u16,
    pub refund_locktime_step: u16,

    pub first_connect_attempts: u32,
    pub first_connect_sleep_delay_sec: u64,
    pub first_connect_attempt_timeout_sec: u64,

    pub reconnect_attempts: u32,
    pub reconnect_short_sleep_delay: u64,
    pub reconnect_long_sleep_delay: u64,
    pub short_long_sleep_delay_transition: u32,
    pub reconnect_attempt_timeout_sec: u64,
}

impl Default for TakerConfig {
    fn default() -> Self {
        Self {
            refund_locktime: 48,
            refund_locktime_step: 48,
            first_connect_attempts: 5,
            first_connect_sleep_delay_sec: 1,
            first_connect_attempt_timeout_sec: 20,
            reconnect_attempts: 3200,
            reconnect_short_sleep_delay: 10,
            reconnect_long_sleep_delay: 60,
            short_long_sleep_delay_transition: 60,
            reconnect_attempt_timeout_sec: 300,
        }
    }
}

impl TakerConfig {
    pub fn init(file_path: Option<&PathBuf>) -> Self {
        let default_config = Self::default();
        let default_path = PathBuf::from("taker.toml");
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

        let taker_config_section = match sections.get("taker_config") {
            Some(config) => config,
            None => {
                eprintln!("'taker_config' section not found in config file");
                return default_config;
            }
        };

        Self {
            refund_locktime: parse_field(
                "refund_locktime",
                taker_config_section.get("refund_locktime"),
                default_config.refund_locktime,
            ),
            refund_locktime_step: parse_field(
                "refund_locktime_step",
                taker_config_section.get("refund_locktime_step"),
                default_config.refund_locktime_step,
            ),
            first_connect_attempts: parse_field(
                "first_connect_attempts",
                taker_config_section.get("first_connect_attempts"),
                default_config.first_connect_attempts,
            ),
            first_connect_sleep_delay_sec: parse_field(
                "first_connect_sleep_delay_sec",
                taker_config_section.get("first_connect_sleep_delay_sec"),
                default_config.first_connect_sleep_delay_sec,
            ),
            first_connect_attempt_timeout_sec: parse_field(
                "first_connect_attempt_timeout_sec",
                taker_config_section.get("first_connect_attempt_timeout_sec"),
                default_config.first_connect_attempt_timeout_sec,
            ),
            reconnect_attempts: parse_field(
                "reconnect_attempts",
                taker_config_section.get("reconnect_attempts"),
                default_config.reconnect_attempts,
            ),
            reconnect_short_sleep_delay: parse_field(
                "reconnect_short_sleep_delay",
                taker_config_section.get("reconnect_short_sleep_delay"),
                default_config.reconnect_short_sleep_delay,
            ),
            reconnect_long_sleep_delay: parse_field(
                "reconnect_long_sleep_delay",
                taker_config_section.get("reconnect_long_sleep_delay"),
                default_config.reconnect_long_sleep_delay,
            ),
            short_long_sleep_delay_transition: parse_field(
                "short_long_sleep_delay_transition",
                taker_config_section.get("short_long_sleep_delay_transition"),
                default_config.short_long_sleep_delay_transition,
            ),
            reconnect_attempt_timeout_sec: parse_field(
                "reconnect_attempt_timeout_sec",
                taker_config_section.get("reconnect_attempt_timeout_sec"),
                default_config.reconnect_attempt_timeout_sec,
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
        [taker_config]
        refund_locktime = 48
        refund_locktime_step = 48
        first_connect_attempts = 5
        first_connect_sleep_delay_sec = 1
        first_connect_attempt_timeout_sec = 20
        reconnect_attempts = 3200
        reconnect_short_sleep_delay = 10
        reconnect_long_sleep_delay = 60
        short_long_sleep_delay_transition = 60
        reconnect_attempt_timeout_sec = 300
        "#;
        let config_path = create_temp_config(contents, "valid_taker_config.toml");
        let config = TakerConfig::init(Some(&config_path));
        remove_temp_config(&config_path);

        let default_config = TakerConfig::default();
        assert_eq!(config, default_config);
    }

    #[test]
    fn test_missing_fields() {
        let contents = r#"
            [taker_config]
            refund_locktime = 48
        "#;
        let config_path = create_temp_config(contents, "missing_fields_taker_config.toml");
        let config = TakerConfig::init(Some(&config_path));
        remove_temp_config(&config_path);

        assert_eq!(config.refund_locktime, 48);
        assert_eq!(config, TakerConfig::default());
    }

    #[test]
    fn test_incorrect_data_type() {
        let contents = r#"
            [taker_config]
            refund_locktime = "not_a_number"
        "#;
        let config_path = create_temp_config(contents, "incorrect_type_taker_config.toml");
        let config = TakerConfig::init(Some(&config_path));
        remove_temp_config(&config_path);

        assert_eq!(config, TakerConfig::default());
    }

    #[test]
    fn test_different_data() {
        let contents = r#"
            [taker_config]
            refund_locktime = 49
        "#;
        let config_path = create_temp_config(contents, "different_data_taker_config.toml");
        let config = TakerConfig::init(Some(&config_path));
        remove_temp_config(&config_path);
        assert_eq!(config.refund_locktime, 49);
        assert_eq!(
            TakerConfig {
                refund_locktime: 48,
                ..config
            },
            TakerConfig::default()
        )
    }
}
