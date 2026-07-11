//! IPv4 range filter (`ipfilter.dat`) mirroring the eMuleBB master `CIPFilter`.
//!
//! Lines use the classic eMule format `start - end [, level [, description]]`
//! with host-order dotted IPv4 addresses, plus the PeerGuardian
//! `description:start-end` format. An address is filtered when it falls inside a
//! range whose `level` is **below** the configured filter level (default 127),
//! matching `CIPFilter::IsFiltered` (`range.level < level`). Ranges parsed
//! without an explicit level default to 100, so they are filtered by default.

use std::{net::Ipv4Addr, sync::Arc};

use parking_lot::RwLock;

/// eMule default level for ranges parsed without an explicit level token.
pub const DEFAULT_RANGE_LEVEL: u32 = 100;
/// eMule default filter level threshold (`Preferences` `FilterLevel`).
pub const DEFAULT_FILTER_LEVEL: u32 = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRange {
    start: u32,
    end: u32,
    level: u32,
}

/// The mutable backing of an [`IpFilter`]: the sorted ranges + the level
/// threshold. Held behind a shared `RwLock` so a reload swaps it in place for
/// every clone (mirroring `CIPFilter::Reload` re-reading `ipfilter.dat` on
/// demand: the live filter changes without re-plumbing every consumer).
#[derive(Debug, Default)]
struct IpFilterInner {
    ranges: Vec<IpRange>,
    filter_level: u32,
}

/// A loaded, sorted set of filtered IPv4 ranges.
///
/// `Clone` shares the same backing store (`Arc`), so reloading one handle via
/// [`IpFilter::reload_from`] is observed by every clone -- including the ones
/// captured at startup into the listener, the Kad traversal IP-filter closure,
/// and the UDP reask loop. `CIPFilter::Reload` parity.
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    inner: Arc<RwLock<IpFilterInner>>,
}

impl IpFilter {
    /// Parse an `ipfilter.dat` body. Unparseable lines are skipped (matching the
    /// master's lenient line-by-line load). `filter_level` is the threshold an
    /// address's matched range must be below to be filtered.
    #[must_use]
    pub fn parse(body: &str, filter_level: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(parse_inner(body, filter_level))),
        }
    }

    /// Re-parse `body` at `filter_level` and swap it into this filter's shared
    /// backing, so every clone observes the new ranges (`CIPFilter::Reload`).
    pub fn reload_from(&self, body: &str, filter_level: u32) {
        let inner = parse_inner(body, filter_level);
        *self.inner.write() = inner;
    }

    /// Number of loaded ranges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().ranges.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().ranges.is_empty()
    }

    /// Whether `ip` is filtered: it is contained in a range whose level is below
    /// the configured filter level. An empty filter never filters.
    #[must_use]
    pub fn is_filtered(&self, ip: Ipv4Addr) -> bool {
        let inner = self.inner.read();
        if inner.ranges.is_empty() {
            return false;
        }
        let value = u32::from(ip);
        inner
            .ranges
            .iter()
            .filter(|range| range.start <= value && value <= range.end)
            .any(|range| range.level < inner.filter_level)
    }
}

fn parse_inner(body: &str, filter_level: u32) -> IpFilterInner {
    let mut ranges: Vec<IpRange> = body
        .lines()
        .filter_map(parse_filter_line)
        .filter(|range| range.start <= range.end)
        .collect();
    // Sort by range start so lookups can short-circuit; overlapping ranges
    // are tolerated (the first containing range with a filtering level wins).
    ranges.sort_by_key(|range| (range.start, range.end));
    IpFilterInner {
        ranges,
        filter_level,
    }
}

fn parse_filter_line(line: &str) -> Option<IpRange> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    parse_emule_line(trimmed).or_else(|| parse_peerguardian_line(trimmed))
}

/// `start - end [, level [, description]]`
fn parse_emule_line(line: &str) -> Option<IpRange> {
    let (range_part, rest) = match line.split_once(',') {
        Some((range_part, rest)) => (range_part, Some(rest)),
        None => (line, None),
    };
    let (start_text, end_text) = range_part.split_once('-')?;
    let start = parse_ipv4(start_text.trim())?;
    let end = parse_ipv4(end_text.trim())?;
    let level = match rest {
        None => DEFAULT_RANGE_LEVEL,
        Some(rest) => {
            let level_text = rest.split(',').next().unwrap_or("").trim();
            level_text.parse::<u32>().ok()?
        }
    };
    Some(IpRange { start, end, level })
}

/// PeerGuardian: `description:start-end`
fn parse_peerguardian_line(line: &str) -> Option<IpRange> {
    let (_, range_part) = line.rsplit_once(':')?;
    let (start_text, end_text) = range_part.split_once('-')?;
    let start = parse_ipv4(start_text.trim())?;
    let end = parse_ipv4(end_text.trim())?;
    Some(IpRange {
        start,
        end,
        level: DEFAULT_RANGE_LEVEL,
    })
}

fn parse_ipv4(text: &str) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in text.split('.') {
        if count == 4 {
            return None;
        }
        octets[count] = part.trim().parse::<u8>().ok()?;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(u32::from(Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_emule_format_and_filters_default_level() {
        let filter = IpFilter::parse(
            "001.002.003.000 - 001.002.003.255 , 100 , Blocked range\n# comment\n",
            DEFAULT_FILTER_LEVEL,
        );
        assert_eq!(filter.len(), 1);
        assert!(filter.is_filtered(Ipv4Addr::new(1, 2, 3, 50)));
        assert!(!filter.is_filtered(Ipv4Addr::new(1, 2, 4, 0)));
    }

    #[test]
    fn high_level_ranges_are_allow_listed() {
        // A range with level >= the filter level is not filtered (allow entry).
        let filter = IpFilter::parse(
            "10.0.0.0 - 10.0.0.255 , 200 , Allowed",
            DEFAULT_FILTER_LEVEL,
        );
        assert!(!filter.is_filtered(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn line_without_level_defaults_to_filtered() {
        let filter = IpFilter::parse("5.6.7.0 - 5.6.7.255", DEFAULT_FILTER_LEVEL);
        assert!(filter.is_filtered(Ipv4Addr::new(5, 6, 7, 8)));
    }

    #[test]
    fn parses_peerguardian_format() {
        let filter = IpFilter::parse("Some Org:9.9.9.0-9.9.9.255", DEFAULT_FILTER_LEVEL);
        assert!(filter.is_filtered(Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn reload_swaps_ranges_for_every_clone() {
        // CIPFilter::Reload parity: re-parsing the file swaps the live ranges,
        // and a clone captured before the reload observes the new content
        // (shared Arc backing).
        let filter = IpFilter::parse("1.2.3.0 - 1.2.3.255 , 100 , old", DEFAULT_FILTER_LEVEL);
        let captured = filter.clone();
        assert!(captured.is_filtered(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(!captured.is_filtered(Ipv4Addr::new(9, 9, 9, 9)));

        filter.reload_from("9.9.9.0 - 9.9.9.255 , 100 , new", DEFAULT_FILTER_LEVEL);
        // The clone now sees the reloaded set: old range gone, new range active.
        assert!(!captured.is_filtered(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(captured.is_filtered(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(captured.len(), 1);
    }

    #[test]
    fn empty_filter_never_filters() {
        let filter = IpFilter::parse("", DEFAULT_FILTER_LEVEL);
        assert!(filter.is_empty());
        assert!(!filter.is_filtered(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
