//! Amounts on the wire, exactly.
//!
//! Bitcoin Core's RPC carries amounts as JSON numbers, and every client an exchange runs expects
//! them there. A JSON number read through a double loses nano-HLX above ~9 million HLX and turns
//! `2.01` into 2.009999999 (#257), so this service never lets one pass through a float: amounts are
//! read from the literal text of the request and written as literal text into the answer.

use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

/// Nano-HLX per HLX.
pub const NANO: i128 = 1_000_000_000;

/// A signed amount in nano-HLX, written as a JSON number with nine decimals (`-1.250000000`) —
/// fixed places, as Bitcoin Core writes eight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Hlx(pub i128);

impl Hlx {
    pub fn literal(self) -> String {
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        format!("{sign}{}.{:09}", abs / NANO as u128, abs % NANO as u128)
    }
}

impl Serialize for Hlx {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = RawValue::from_string(self.literal()).map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}

/// An amount from a request: a JSON number or a string holding one, read as its digits.
/// Anything `helix_core::fee::parse_hlx` would refuse (`1e3`, a tenth decimal, a minus sign) is
/// refused here — before anything is signed.
pub fn parse(raw: &RawValue) -> Result<u64, String> {
    let text = raw.get().trim();
    let digits = if text.starts_with('"') {
        serde_json::from_str::<String>(text).map_err(|_| format!("{text} is not an amount"))?
    } else {
        text.to_string()
    };
    helix_core::fee::parse_hlx(digits.trim()).map_err(|e| format!("invalid amount {text}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str) -> Box<RawValue> {
        RawValue::from_string(text.to_string()).unwrap()
    }

    #[test]
    fn an_amount_is_written_as_its_digits() {
        assert_eq!(Hlx(0).literal(), "0.000000000");
        assert_eq!(Hlx(2_010_000_000).literal(), "2.010000000");
        assert_eq!(Hlx(-1).literal(), "-0.000000001");
        // 33 million HLX to the nano, which no double carries.
        assert_eq!(Hlx(33_000_000_000_000_001).literal(), "33000000.000000001");
        assert_eq!(serde_json::to_string(&Hlx(-5_000_000_000)).unwrap(), "-5.000000000");
    }

    #[test]
    fn an_amount_is_read_as_its_digits_whether_number_or_string() {
        assert_eq!(parse(&raw("2.01")).unwrap(), 2_010_000_000);
        assert_eq!(parse(&raw("\"2.01\"")).unwrap(), 2_010_000_000);
        // Bitcoin clients send eight fixed decimals; nine are the most HLX has.
        assert_eq!(parse(&raw("0.10000000")).unwrap(), 100_000_000);
        assert_eq!(parse(&raw("33000000.000000001")).unwrap(), 33_000_000_000_000_001);
        for refused in ["1e3", "-1", "0.0000000001", "\"abc\"", "null", "true"] {
            assert!(parse(&raw(refused)).is_err(), "{refused} must be refused");
        }
    }

    #[test]
    fn every_cent_survives_the_round_trip() {
        for cents in 1..10_000i128 {
            let text = format!("{}.{:02}", cents / 100, cents % 100);
            let nano = parse(&raw(&text)).unwrap() as i128;
            assert_eq!(nano, cents * NANO / 100, "{text}");
            assert_eq!(parse(&raw(&Hlx(nano).literal())).unwrap() as i128, nano);
        }
    }
}
