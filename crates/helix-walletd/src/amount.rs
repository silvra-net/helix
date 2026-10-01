//! Amounts on the wire, exactly.
//!
//! Bitcoin Core's RPC carries amounts as JSON numbers, and every client an exchange runs expects
//! them there. A JSON number read through a double loses nano-HLX above ~9 million HLX and turns
//! `2.01` into 2.009999999 (#257), so this service never lets one pass through a float: amounts are
//! read from the literal text of the request and written as literal text into the answer.
//!
//! **Eight or nine decimals.** HLX has nine. A Bitcoin-family integration often stores eight — a
//! database column, a fixed-point type — and would cut a ninth off silently. With
//! `amountdecimals=8` every amount is written with eight, rounded the way that can never cost the
//! exchange: toward −∞. A credit (a deposit, a balance) is never shown larger than it is, a debit
//! (a send, a fee) never smaller; fee *rates* round up. And amounts with a ninth decimal are
//! refused on the way in, as Bitcoin Core refuses a ninth.

use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

/// Nano-HLX per HLX.
pub const NANO: i128 = 1_000_000_000;

/// How many decimals amounts are written and read with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Decimals {
    /// What a Bitcoin-family integration stores; the ninth is rounded off.
    Eight,
    /// All of HLX.
    #[default]
    Nine,
}

impl Decimals {
    pub fn parse(text: &str) -> Result<Decimals, String> {
        match text.trim() {
            "8" => Ok(Decimals::Eight),
            "9" => Ok(Decimals::Nine),
            other => Err(format!("{other:?} is not 8 or 9")),
        }
    }

    /// Nano-HLX in one unit of the last decimal.
    fn step(self) -> i128 {
        match self {
            Decimals::Eight => 10,
            Decimals::Nine => 1,
        }
    }
}

/// A signed amount as an answer writes it: a JSON number with fixed places (`-1.250000000`), as
/// Bitcoin Core writes eight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hlx {
    nano: i128,
    decimals: Decimals,
}

impl Hlx {
    /// Exact, nine decimals.
    pub fn exact(nano: i128) -> Hlx {
        Hlx { nano, decimals: Decimals::Nine }
    }

    /// Rounded toward −∞: for amounts — a credit is never shown larger than it is, a debit never
    /// smaller.
    pub fn down(nano: i128, decimals: Decimals) -> Hlx {
        let step = decimals.step();
        Hlx { nano: nano.div_euclid(step) * step, decimals }
    }

    /// Rounded toward +∞: for fee rates — never shown below what is charged.
    pub fn up(nano: i128, decimals: Decimals) -> Hlx {
        let step = decimals.step();
        Hlx { nano: -(-nano).div_euclid(step) * step, decimals }
    }

    /// The nano-HLX this writes, after rounding.
    pub fn nano(self) -> i128 {
        self.nano
    }

    pub fn literal(self) -> String {
        let sign = if self.nano < 0 { "-" } else { "" };
        let abs = self.nano.unsigned_abs();
        let (whole, frac) = (abs / NANO as u128, abs % NANO as u128);
        match self.decimals {
            Decimals::Nine => format!("{sign}{whole}.{frac:09}"),
            Decimals::Eight => format!("{sign}{whole}.{:08}", frac / 10),
        }
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
/// refused here — before anything is signed — and so is a ninth decimal when the wallet works in
/// eight.
pub fn parse(raw: &RawValue, decimals: Decimals) -> Result<u64, String> {
    let text = raw.get().trim();
    let digits = if text.starts_with('"') {
        serde_json::from_str::<String>(text).map_err(|_| format!("{text} is not an amount"))?
    } else {
        text.to_string()
    };
    let nano = helix_core::fee::parse_hlx(digits.trim()).map_err(|e| format!("invalid amount {text}: {e}"))?;
    if nano as i128 % decimals.step() != 0 {
        return Err(format!(
            "invalid amount {text}: this wallet works in eight decimals (amountdecimals=8), and this \
             has a ninth"
        ));
    }
    Ok(nano)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str) -> Box<RawValue> {
        RawValue::from_string(text.to_string()).unwrap()
    }

    #[test]
    fn an_amount_is_written_as_its_digits() {
        assert_eq!(Hlx::exact(0).literal(), "0.000000000");
        assert_eq!(Hlx::exact(2_010_000_000).literal(), "2.010000000");
        assert_eq!(Hlx::exact(-1).literal(), "-0.000000001");
        // 33 million HLX to the nano, which no double carries.
        assert_eq!(Hlx::exact(33_000_000_000_000_001).literal(), "33000000.000000001");
        assert_eq!(serde_json::to_string(&Hlx::exact(-5_000_000_000)).unwrap(), "-5.000000000");
    }

    #[test]
    fn an_amount_is_read_as_its_digits_whether_number_or_string() {
        let nine = Decimals::Nine;
        assert_eq!(parse(&raw("2.01"), nine).unwrap(), 2_010_000_000);
        assert_eq!(parse(&raw("\"2.01\""), nine).unwrap(), 2_010_000_000);
        // Bitcoin clients send eight fixed decimals; nine are the most HLX has.
        assert_eq!(parse(&raw("0.10000000"), nine).unwrap(), 100_000_000);
        assert_eq!(parse(&raw("33000000.000000001"), nine).unwrap(), 33_000_000_000_000_001);
        for refused in ["1e3", "-1", "0.0000000001", "\"abc\"", "null", "true"] {
            assert!(parse(&raw(refused), nine).is_err(), "{refused} must be refused");
        }
    }

    #[test]
    fn every_cent_survives_the_round_trip() {
        for cents in 1..10_000i128 {
            let text = format!("{}.{:02}", cents / 100, cents % 100);
            for decimals in [Decimals::Eight, Decimals::Nine] {
                let nano = parse(&raw(&text), decimals).unwrap() as i128;
                assert_eq!(nano, cents * NANO / 100, "{text}");
                assert_eq!(parse(&raw(&Hlx::down(nano, decimals).literal()), decimals).unwrap() as i128, nano);
            }
        }
    }

    /// With eight decimals the ninth is never shown in the exchange's favour: a deposit of
    /// 1.000000009 is written 1.00000000, a fee of 0.000000001 as -0.00000001, a fee rate of
    /// 0.000000001 per kB as 0.00000001.
    #[test]
    fn eight_decimals_round_in_the_direction_that_cannot_cost_the_exchange() {
        let eight = Decimals::Eight;
        assert_eq!(Hlx::down(1_000_000_009, eight).literal(), "1.00000000", "a credit rounds down");
        assert_eq!(Hlx::down(-1, eight).literal(), "-0.00000001", "a debit rounds away from zero");
        assert_eq!(Hlx::down(-1_000_000_000, eight).literal(), "-1.00000000", "an exact debit stays");
        assert_eq!(Hlx::up(1, eight).literal(), "0.00000001", "a fee rate rounds up");
        assert_eq!(Hlx::up(0, eight).literal(), "0.00000000");
        assert_eq!(Hlx::down(1_000_000_009, Decimals::Nine).literal(), "1.000000009", "nine stays exact");
        for nano in [-1_000_000_009i128, -11, -10, -9, -1, 0, 1, 9, 10, 11, 1_000_000_009] {
            assert!(Hlx::down(nano, eight).nano() <= nano, "{nano} shown as more");
            assert!(Hlx::up(nano, eight).nano() >= nano, "{nano} rate shown as less");
            assert!(nano - Hlx::down(nano, eight).nano() < 10, "{nano} rounded by more than one step");
        }
    }

    #[test]
    fn eight_decimals_refuse_a_ninth_on_the_way_in() {
        let eight = Decimals::Eight;
        assert_eq!(parse(&raw("0.12345678"), eight).unwrap(), 123_456_780);
        let err = parse(&raw("0.123456789"), eight).unwrap_err();
        assert!(err.contains("eight decimals"), "{err}");
        assert_eq!(Decimals::parse("8"), Ok(Decimals::Eight));
        assert!(Decimals::parse("6").is_err());
    }
}
