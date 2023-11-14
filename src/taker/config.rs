use crate::utill::parse_toml;

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
        let sections = parse_toml("config.toml").unwrap();
        let taker_config_section = sections.get("taker_config").unwrap();

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
    use super::TakerConfig;

    #[test]
    fn test_parsing_toml_taker() {
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
        let parsed_taker = TakerConfig::default();
        assert_eq!(dummy_taker, parsed_taker);
    }
}
