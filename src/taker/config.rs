use std::path::PathBuf;

use crate::utill::parse_toml;

//relatively low value for now so that its easier to test without having to wait too much
//right now only the very brave will try coinswap out on mainnet with non-trivial amounts
pub const REFUND_LOCKTIME: u16 = 48; //in blocks
pub const REFUND_LOCKTIME_STEP: u16 = 48; //in blocks

//first connect means the first time you're ever connecting, without having gotten any txes
// confirmed yet, so the taker will not be very persistent since there should be plenty of other
// makers out there
//but also it should allow for flaky connections, otherwise you exclude raspberry pi nodes running
// in people's closets, which are very important for decentralization
pub const FIRST_CONNECT_ATTEMPTS: u32 = 5;
pub const FIRST_CONNECT_SLEEP_DELAY_SEC: u64 = 1;
pub const FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC: u64 = 20;

//reconnect means when connecting to a maker again after having already gotten txes confirmed
// as it would be a waste of miner fees to give up, the taker is coded to be very persistent
//taker will first attempt to connect with a short delay between attempts
// after that will attempt to connect with a longer delay between attempts
//these figures imply that taker will attempt to connect for just over 48 hours
// of course the user can ctrl+c before then if they give up themselves
const RECONNECT_ATTEMPTS: u32 = 3200;
const RECONNECT_SHORT_SLEEP_DELAY_SEC: u64 = 10;
const RECONNECT_LONG_SLEEP_DELAY_SEC: u64 = 60;
const SHORT_LONG_SLEEP_DELAY_TRANSITION: u32 = 60; //after this many attempts, switch to sleeping longer
const RECONNECT_ATTEMPT_TIMEOUT_SEC: u64 = 60 * 5;

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
            refund_locktime: REFUND_LOCKTIME,
            refund_locktime_step: REFUND_LOCKTIME_STEP,
            first_connect_attempts: FIRST_CONNECT_ATTEMPTS,
            first_connect_sleep_delay_sec: FIRST_CONNECT_SLEEP_DELAY_SEC,
            first_connect_attempt_timeout_sec: FIRST_CONNECT_ATTEMPT_TIMEOUT_SEC,
            reconnect_attempts: RECONNECT_ATTEMPTS,
            reconnect_short_sleep_delay: RECONNECT_SHORT_SLEEP_DELAY_SEC,
            reconnect_long_sleep_delay: RECONNECT_LONG_SLEEP_DELAY_SEC,
            short_long_sleep_delay_transition: SHORT_LONG_SLEEP_DELAY_TRANSITION,
            reconnect_attempt_timeout_sec: RECONNECT_ATTEMPT_TIMEOUT_SEC,
        }
    }
}

impl TakerConfig {
    pub fn init(file_path: Option<&PathBuf>) -> Self {
        let sections = if let Some(path) = file_path {
            parse_toml(path)
        } else {
            parse_toml(&PathBuf::from("taker.toml"))
        };

        if sections.is_err() {
            return Self {
                ..TakerConfig::default()
            };
        }

        let section = sections.unwrap();

        if let None = section.get("taker_config") {
            return Self {
                ..TakerConfig::default()
            };
        }

        let taker_config_section = section.get("taker_config").unwrap();

        let taker_keys = vec![
            "reconnect_short_sleep_delay",
            "reconnect_attempts",
            "first_connect_attempt_timeout_sec",
            "refund_locktime",
            "first_connect_sleep_delay_sec",
            "reconnect_long_sleep_delay",
            "reconnect_attempt_timeout_sec",
            "refund_locktime_step",
            "first_connect_attempts",
            "short_long_sleep_delay_transition",
        ];

        for x in taker_keys.iter() {
            if taker_config_section.contains_key(*x) == false {
                return Self {
                    ..TakerConfig::default()
                };
            }
        }

        TakerConfig {
            reconnect_short_sleep_delay: taker_config_section
                .get("reconnect_short_sleep_delay")
                .unwrap()
                .parse()
                .unwrap(),
            reconnect_attempts: taker_config_section
                .get("reconnect_attempts")
                .unwrap()
                .parse()
                .unwrap(),
            first_connect_attempt_timeout_sec: taker_config_section
                .get("first_connect_attempt_timeout_sec")
                .unwrap()
                .parse()
                .unwrap(),
            refund_locktime: taker_config_section
                .get("refund_locktime")
                .unwrap()
                .parse()
                .unwrap(),
            first_connect_sleep_delay_sec: taker_config_section
                .get("first_connect_sleep_delay_sec")
                .unwrap()
                .parse()
                .unwrap(),
            reconnect_long_sleep_delay: taker_config_section
                .get("reconnect_long_sleep_delay")
                .unwrap()
                .parse()
                .unwrap(),
            reconnect_attempt_timeout_sec: taker_config_section
                .get("reconnect_attempt_timeout_sec")
                .unwrap()
                .parse()
                .unwrap(),
            refund_locktime_step: taker_config_section
                .get("refund_locktime_step")
                .unwrap()
                .parse()
                .unwrap(),
            first_connect_attempts: taker_config_section
                .get("first_connect_attempts")
                .unwrap()
                .parse()
                .unwrap(),
            short_long_sleep_delay_transition: taker_config_section
                .get("short_long_sleep_delay_transition")
                .unwrap()
                .parse()
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::TakerConfig;

    #[test]
    fn test_parsing_toml_taker_all_works() {
        let dummy_taker = TakerConfig {
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
        };
        let parsed_taker = TakerConfig::init(Some(&PathBuf::from("taker.toml")));
        // parsing the correct file
        assert_eq!(dummy_taker, parsed_taker);
    }

    #[test]
    fn test_parsing_toml_taker_file_missing() {
        let dummy_taker = TakerConfig {
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
        };
        let parsed_taker = TakerConfig::init(Some(&PathBuf::from("take.toml")));
        // Taking Default Path, when file is not present
        assert_eq!(dummy_taker, parsed_taker);
    }

    #[test]
    fn test_parsing_toml_taker_wrong_file() {
        let dummy_taker = TakerConfig {
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
        };
        let parsed_taker = TakerConfig::init(Some(&PathBuf::from("cargo.toml")));
        // Taking Default Path, when wrong file is input
        assert_eq!(dummy_taker, parsed_taker);
    }

    #[test]
    fn test_parsing_toml_taker_faulty_data() {
        let dummy_taker = TakerConfig {
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
        };
        let parsed_taker = TakerConfig::init(Some(&PathBuf::from("config.toml")));
        // Taking Default Path, when few fields are missing
        assert_eq!(dummy_taker, parsed_taker);
    }
}
