//! Exact saved-settings CAS tokens, independent of wall clocks and JSON numbers.
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettingsRevision(i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsRevisionError {
    Invalid,
    Exhausted,
}
impl fmt::Display for SettingsRevisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Invalid settings revision.",
            Self::Exhausted => "Settings revision is exhausted.",
        })
    }
}
impl std::error::Error for SettingsRevisionError {}

impl SettingsRevision {
    pub const INITIAL: Self = Self(1);
    pub fn from_i64(value: i64) -> Result<Self, SettingsRevisionError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(SettingsRevisionError::Invalid)
        }
    }
    pub fn get(self) -> i64 {
        self.0
    }
    pub fn checked_next(self) -> Result<Self, SettingsRevisionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(SettingsRevisionError::Exhausted)
    }
}
impl fmt::Display for SettingsRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for SettingsRevision {
    type Err = SettingsRevisionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SettingsRevisionError::Invalid);
        }
        Self::from_i64(value.parse().map_err(|_| SettingsRevisionError::Invalid)?)
    }
}
impl Serialize for SettingsRevision {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for SettingsRevision {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revision_is_an_exact_positive_decimal_string_and_never_wraps() {
        for value in [1, 9_007_199_254_740_993, i64::MAX] {
            let revision = SettingsRevision::from_i64(value).unwrap();
            let json = serde_json::to_string(&revision).unwrap();
            assert_eq!(json, format!("\"{value}\""));
            assert_eq!(
                serde_json::from_str::<SettingsRevision>(&json).unwrap(),
                revision
            );
        }
        assert_eq!(SettingsRevision::INITIAL.checked_next().unwrap().get(), 2);
        assert_eq!(
            SettingsRevision::from_i64(i64::MAX).unwrap().checked_next(),
            Err(SettingsRevisionError::Exhausted)
        );
        for text in [
            "",
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.0",
            "1e2",
            "9223372036854775808",
            "１２",
        ] {
            assert!(text.parse::<SettingsRevision>().is_err());
        }
        for json in ["1", "null", "true"] {
            assert!(serde_json::from_str::<SettingsRevision>(json).is_err());
        }
    }
}
