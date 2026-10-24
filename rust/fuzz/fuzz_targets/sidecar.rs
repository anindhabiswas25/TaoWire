//! cargo fuzz target on the sidecar answer parsers (spec 11.6): arbitrary
//! sidecar JSON never panics and never admits a caller the answer does not
//! really list with a validator permit; `/v1/caller` allows only for exactly
//! `{"allowed": true}`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tensorwire_btauth::sidecar::{
    parse_decision, parse_health, parse_snapshot, CallerPolicy, Decision,
};

const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = parse_snapshot(data, 2) {
        let listed = s.by_hotkey(ALICE).is_some_and(|n| n.validator_permit);
        assert_eq!(CallerPolicy::default().check(ALICE, &s).is_ok(), listed);
    }
    if let Ok(Decision::Allowed) = parse_decision(data) {
        let v: serde_json::Value = serde_json::from_slice(data).expect("parsed once already");
        assert_eq!(v, serde_json::json!({"allowed": true}));
    }
    let _ = parse_health(data);
});
