use super::parse;

#[test]
fn neither_cache_window_can_be_configured_past_the_ceiling() {
    // Both windows bound how long a value the vendor has replaced can
    // still reach a child, so neither is a number a config file may set to
    // a day. A config is not a trusted input: it can be handed in with
    // `--config`.
    let config = parse(r#"{"cache_ttl_seconds": 86400, "cache_stale_seconds": 86400}"#);
    assert_eq!(
        config.ttl().as_secs(),
        crate::daemon::config::MAX_CACHE_SECONDS
    );
    assert_eq!(
        config.stale().as_secs(),
        crate::daemon::config::MAX_CACHE_SECONDS
    );
}

#[test]
fn caching_switched_off_leaves_no_stale_window_behind() {
    // One key turns the whole mechanism off. A daemon told to cache
    // nothing must not keep serving values for four minutes because a
    // second key still holds its default.
    let config = parse(r#"{"cache_ttl_seconds": 0}"#);
    assert_eq!(config.ttl(), std::time::Duration::ZERO);
    assert_eq!(
        config.stale(),
        std::time::Duration::ZERO,
        "a zero freshness window left a stale window standing"
    );
}

#[test]
fn a_config_that_names_neither_window_takes_both_defaults() {
    let config = parse("{}");
    assert_eq!(config.ttl().as_secs(), 60);
    assert_eq!(config.stale().as_secs(), 240);
}
