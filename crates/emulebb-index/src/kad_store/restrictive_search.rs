use std::io::{Cursor, Read};

use emulebb_kad_proto::{Tag, TagName, TagValue, kad_lowercase, tag_name};

const MAX_SEARCH_EXPR_DEPTH: u8 = 24;
const INVALID_KAD_KEYWORD_CHARS: &str = " ()[]{}<>,._-!?:;\\/\"";

pub(super) const DEFAULT_RESTRICTIVE_SEARCH_LIMITS: RestrictiveSearchLimits =
    RestrictiveSearchLimits {
        parsed_ast_nodes: 64,
        compared_tag_values: 32_768,
        candidate_entries: 4_096,
        results_emitted: 300,
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RestrictiveSearchLimits {
    pub(super) parsed_ast_nodes: usize,
    pub(super) compared_tag_values: usize,
    pub(super) candidate_entries: usize,
    pub(super) results_emitted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RestrictiveSearchStopReason {
    InvalidPayload,
    ParsedAstNodes,
    ComparedTagValues,
    CandidateEntries,
    ResultsEmitted,
}

impl RestrictiveSearchStopReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_payload",
            Self::ParsedAstNodes => "parsed_ast_nodes",
            Self::ComparedTagValues => "compared_tag_values",
            Self::CandidateEntries => "candidate_entries",
            Self::ResultsEmitted => "results_emitted",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RestrictiveSearchWork {
    pub(super) parsed_ast_nodes: usize,
    pub(super) compared_tag_values: usize,
    pub(super) candidate_entries: usize,
    pub(super) results_emitted: usize,
}

pub(super) struct RestrictiveSearchBudget {
    limits: RestrictiveSearchLimits,
    work: RestrictiveSearchWork,
}

impl RestrictiveSearchBudget {
    pub(super) const fn new(limits: RestrictiveSearchLimits, parsed_ast_nodes: usize) -> Self {
        Self {
            limits,
            work: RestrictiveSearchWork {
                parsed_ast_nodes,
                compared_tag_values: 0,
                candidate_entries: 0,
                results_emitted: 0,
            },
        }
    }

    pub(super) fn examine_candidate(&mut self) -> Result<(), RestrictiveSearchStopReason> {
        if self.work.candidate_entries >= self.limits.candidate_entries {
            return Err(RestrictiveSearchStopReason::CandidateEntries);
        }
        self.work.candidate_entries += 1;
        Ok(())
    }

    pub(super) fn emit_result(&mut self) -> Result<(), RestrictiveSearchStopReason> {
        if self.work.results_emitted >= self.limits.results_emitted {
            return Err(RestrictiveSearchStopReason::ResultsEmitted);
        }
        self.work.results_emitted += 1;
        Ok(())
    }

    pub(super) const fn result_limit(&self, requested: usize) -> usize {
        if requested < self.limits.results_emitted {
            requested
        } else {
            self.limits.results_emitted
        }
    }

    pub(super) const fn work(&self) -> RestrictiveSearchWork {
        self.work
    }

    fn compare_tag_value(&mut self) -> Result<(), RestrictiveSearchStopReason> {
        if self.work.compared_tag_values >= self.limits.compared_tag_values {
            return Err(RestrictiveSearchStopReason::ComparedTagValues);
        }
        self.work.compared_tag_values += 1;
        Ok(())
    }
}

pub(super) struct RestrictiveSearch {
    term: SearchTerm,
    parsed_ast_nodes: usize,
}

impl RestrictiveSearch {
    pub(super) fn parse(
        payload: &[u8],
        limits: RestrictiveSearchLimits,
    ) -> Result<Self, RestrictiveSearchStopReason> {
        let mut parser = SearchParser {
            cursor: Cursor::new(payload),
            parsed_ast_nodes: 0,
            parsed_ast_node_limit: limits.parsed_ast_nodes,
        };
        let term = parser.parse_search_term(0)?;
        Ok(Self {
            term,
            parsed_ast_nodes: parser.parsed_ast_nodes,
        })
    }

    pub(super) const fn parsed_ast_nodes(&self) -> usize {
        self.parsed_ast_nodes
    }

    pub(super) fn matches(
        &self,
        filename: &str,
        tags: &[Tag],
        budget: &mut RestrictiveSearchBudget,
    ) -> Result<bool, RestrictiveSearchStopReason> {
        let filename_lower = kad_lowercase(filename);
        self.term
            .matches_with_lower_filename(&filename_lower, tags, budget)
    }
}

struct SearchParser<'a> {
    cursor: Cursor<&'a [u8]>,
    parsed_ast_nodes: usize,
    parsed_ast_node_limit: usize,
}

impl SearchParser<'_> {
    fn parse_search_term(&mut self, depth: u8) -> Result<SearchTerm, RestrictiveSearchStopReason> {
        if depth >= MAX_SEARCH_EXPR_DEPTH {
            return Err(RestrictiveSearchStopReason::InvalidPayload);
        }
        if self.parsed_ast_nodes >= self.parsed_ast_node_limit {
            return Err(RestrictiveSearchStopReason::ParsedAstNodes);
        }
        self.parsed_ast_nodes += 1;

        let op = self.read_u8()?;
        match op {
            0x00 => self.parse_boolean_term(depth + 1),
            0x01 => {
                let value = self.read_lower_string()?;
                Ok(SearchTerm::String(tokenize_opt_quoted_search_term(&value)))
            }
            0x02 => {
                let value = self.read_lower_string()?;
                let name = self.read_tag_name()?;
                Ok(SearchTerm::MetaString { name, value })
            }
            0x03 => {
                let value = self.read_u32()?;
                self.parse_numeric_term(value.into())
            }
            0x08 => {
                let value = self.read_u64()?;
                self.parse_numeric_term(value)
            }
            _ => Err(RestrictiveSearchStopReason::InvalidPayload),
        }
    }

    fn parse_boolean_term(&mut self, depth: u8) -> Result<SearchTerm, RestrictiveSearchStopReason> {
        let bool_op = self.read_u8()?;
        let left = Box::new(self.parse_search_term(depth)?);
        let right = Box::new(self.parse_search_term(depth)?);
        match bool_op {
            0x00 => Ok(SearchTerm::And(left, right)),
            0x01 => Ok(SearchTerm::Or(left, right)),
            0x02 => Ok(SearchTerm::Not(left, right)),
            _ => Err(RestrictiveSearchStopReason::InvalidPayload),
        }
    }

    fn parse_numeric_term(
        &mut self,
        value: u64,
    ) -> Result<SearchTerm, RestrictiveSearchStopReason> {
        let op = match self.read_u8()? {
            0x00 => NumericOp::Equal,
            0x01 => NumericOp::Greater,
            0x02 => NumericOp::Less,
            0x03 => NumericOp::GreaterEqual,
            0x04 => NumericOp::LessEqual,
            0x05 => NumericOp::NotEqual,
            _ => return Err(RestrictiveSearchStopReason::InvalidPayload),
        };
        let name = self.read_tag_name()?;
        Ok(SearchTerm::Numeric { name, op, value })
    }

    fn read_tag_name(&mut self) -> Result<TagName, RestrictiveSearchStopReason> {
        let len = usize::from(self.read_u16()?);
        let mut bytes = vec![0; len];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        if let [name] = bytes.as_slice() {
            Ok(TagName::Short(*name))
        } else {
            Ok(TagName::Long(String::from_utf8_lossy(&bytes).into_owned()))
        }
    }

    fn read_lower_string(&mut self) -> Result<String, RestrictiveSearchStopReason> {
        let len = usize::from(self.read_u16()?);
        let mut bytes = vec![0; len];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        Ok(kad_lowercase(&String::from_utf8_lossy(&bytes)))
    }

    fn read_u8(&mut self) -> Result<u8, RestrictiveSearchStopReason> {
        let mut bytes = [0; 1];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, RestrictiveSearchStopReason> {
        let mut bytes = [0; 2];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, RestrictiveSearchStopReason> {
        let mut bytes = [0; 4];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, RestrictiveSearchStopReason> {
        let mut bytes = [0; 8];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|_| RestrictiveSearchStopReason::InvalidPayload)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

enum SearchTerm {
    And(Box<SearchTerm>, Box<SearchTerm>),
    Or(Box<SearchTerm>, Box<SearchTerm>),
    Not(Box<SearchTerm>, Box<SearchTerm>),
    String(Vec<String>),
    MetaString {
        name: TagName,
        value: String,
    },
    Numeric {
        name: TagName,
        op: NumericOp,
        value: u64,
    },
}

impl SearchTerm {
    fn matches_with_lower_filename(
        &self,
        filename_lower: &str,
        tags: &[Tag],
        budget: &mut RestrictiveSearchBudget,
    ) -> Result<bool, RestrictiveSearchStopReason> {
        match self {
            Self::And(left, right) => {
                if !left.matches_with_lower_filename(filename_lower, tags, budget)? {
                    return Ok(false);
                }
                right.matches_with_lower_filename(filename_lower, tags, budget)
            }
            Self::Or(left, right) => {
                if left.matches_with_lower_filename(filename_lower, tags, budget)? {
                    return Ok(true);
                }
                right.matches_with_lower_filename(filename_lower, tags, budget)
            }
            Self::Not(left, right) => {
                if !left.matches_with_lower_filename(filename_lower, tags, budget)? {
                    return Ok(false);
                }
                Ok(!right.matches_with_lower_filename(filename_lower, tags, budget)?)
            }
            Self::String(terms) => Ok(string_terms_match(filename_lower, terms)),
            Self::MetaString { name, value } => {
                meta_string_matches(filename_lower, tags, name, value, budget)
            }
            Self::Numeric { name, op, value } => numeric_matches(tags, name, *op, *value, budget),
        }
    }
}

#[derive(Clone, Copy)]
enum NumericOp {
    Equal,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
    NotEqual,
}

fn string_terms_match(filename_lower: &str, terms: &[String]) -> bool {
    !terms.is_empty()
        && terms
            .iter()
            .all(|term| filename_lower.contains(term.as_str()))
}

fn meta_string_matches(
    filename_lower: &str,
    tags: &[Tag],
    name: &TagName,
    value: &str,
    budget: &mut RestrictiveSearchBudget,
) -> Result<bool, RestrictiveSearchStopReason> {
    if matches!(name, TagName::Short(name) if *name == tag_name::FILEFORMAT) {
        return Ok(filename_lower
            .rsplit_once('.')
            .map(|(_, extension)| extension == value)
            .unwrap_or(false));
    }

    for tag in tags {
        budget.compare_tag_value()?;
        if tag.name == *name
            && matches!(
                &tag.value,
                TagValue::String(tag_value) if kad_lowercase(tag_value) == value
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn numeric_matches(
    tags: &[Tag],
    name: &TagName,
    op: NumericOp,
    expected: u64,
    budget: &mut RestrictiveSearchBudget,
) -> Result<bool, RestrictiveSearchStopReason> {
    let Some(actual) = int_tag_value(tags, name, budget)? else {
        return Ok(false);
    };
    Ok(match op {
        NumericOp::Equal => actual == expected,
        NumericOp::Greater => actual > expected,
        NumericOp::Less => actual < expected,
        NumericOp::GreaterEqual => actual >= expected,
        NumericOp::LessEqual => actual <= expected,
        NumericOp::NotEqual => actual != expected,
    })
}

fn int_tag_value(
    tags: &[Tag],
    name: &TagName,
    budget: &mut RestrictiveSearchBudget,
) -> Result<Option<u64>, RestrictiveSearchStopReason> {
    if matches!(name, TagName::Short(name) if *name == tag_name::FILESIZE) {
        return file_size_tag_value(tags, budget);
    }

    for tag in tags {
        budget.compare_tag_value()?;
        if tag.name != *name {
            continue;
        }
        let value = match tag.value {
            TagValue::UInt(value) | TagValue::U64(value) => Some(value),
            TagValue::U32(value) => Some(u64::from(value)),
            TagValue::U16(value) => Some(u64::from(value)),
            TagValue::U8(value) => Some(u64::from(value)),
            _ => None,
        };
        if value.is_some() {
            return Ok(value);
        }
    }
    Ok(None)
}

fn file_size_tag_value(
    tags: &[Tag],
    budget: &mut RestrictiveSearchBudget,
) -> Result<Option<u64>, RestrictiveSearchStopReason> {
    let mut size = None;
    let mut size_low = None;
    let mut size_high = None;

    for tag in tags {
        budget.compare_tag_value()?;
        match (&tag.name, &tag.value) {
            (TagName::Short(name), TagValue::UInt(value))
                if *name == tag_name::FILESIZE && u32::try_from(*value).is_ok() =>
            {
                size_low.get_or_insert(*value as u32);
            }
            (TagName::Short(name), TagValue::UInt(value)) if *name == tag_name::FILESIZE => {
                size.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U64(value)) if *name == tag_name::FILESIZE => {
                size.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U32(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U16(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::U8(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::SmallBlob(bytes))
                if *name == tag_name::FILESIZE && bytes.len() == 8 =>
            {
                let mut size_bytes = [0; 8];
                size_bytes.copy_from_slice(bytes);
                size.get_or_insert(u64::from_le_bytes(size_bytes));
            }
            (TagName::Short(name), TagValue::UInt(value))
                if *name == tag_name::FILESIZE_HI && u32::try_from(*value).is_ok() =>
            {
                size_high.get_or_insert(*value as u32);
            }
            (TagName::Short(name), TagValue::U32(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U16(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::U8(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(u32::from(*value));
            }
            _ => {}
        }
    }

    Ok(size.or_else(|| {
        size_low.map(|low| {
            let high = size_high.unwrap_or(0);
            (u64::from(high) << 32) | u64::from(low)
        })
    }))
}

fn tokenize_opt_quoted_search_term(value: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars = value.chars().collect::<Vec<_>>();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] == '"' {
            let start = index + 1;
            if let Some(relative_end) = chars[start..]
                .iter()
                .position(|character| *character == '"')
            {
                let end = start + relative_end;
                if end > start {
                    terms.push(chars[start..end].iter().collect());
                }
                index = end + 1;
            } else {
                index = start;
            }
            continue;
        }

        let start = index;
        while index < chars.len() && !INVALID_KAD_KEYWORD_CHARS.contains(chars[index]) {
            index += 1;
        }
        if index > start {
            terms.push(chars[start..index].iter().collect());
        }
        if index < chars.len() && chars[index] == '"' {
            continue;
        }
        index += 1;
    }

    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::matches_restrictive_keyword_payload;

    #[test]
    fn parsed_matcher_preserves_protocol_match_semantics() {
        let filename = "Ubuntu Linux.iso";
        let tags = vec![
            Tag::filename(filename),
            Tag::filesize(123),
            Tag::new_short(0xF1, TagValue::String("VIDEO".into())),
        ];
        let payloads = [
            string_payload("ubuntu"),
            meta_string_payload("video", 0xF1),
            numeric_payload(100, 0x01, tag_name::FILESIZE),
            boolean_payload(
                0x00,
                string_payload("ubuntu"),
                meta_string_payload("iso", tag_name::FILEFORMAT),
            ),
            boolean_payload(0x01, string_payload("fedora"), string_payload("ubuntu")),
            boolean_payload(0x02, string_payload("ubuntu"), string_payload("server")),
        ];

        for payload in payloads {
            let search = RestrictiveSearch::parse(&payload, DEFAULT_RESTRICTIVE_SEARCH_LIMITS)
                .expect("valid restrictive search");
            let mut budget = RestrictiveSearchBudget::new(
                DEFAULT_RESTRICTIVE_SEARCH_LIMITS,
                search.parsed_ast_nodes(),
            );
            assert_eq!(
                search
                    .matches(filename, &tags, &mut budget)
                    .expect("within budget"),
                matches_restrictive_keyword_payload(filename, &tags, &payload),
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn parser_rejects_expression_over_ast_node_budget() {
        let payload = and_payload(string_payload("ubuntu"), string_payload("linux"));
        let limits = RestrictiveSearchLimits {
            parsed_ast_nodes: 2,
            ..DEFAULT_RESTRICTIVE_SEARCH_LIMITS
        };

        assert!(matches!(
            RestrictiveSearch::parse(&payload, limits),
            Err(RestrictiveSearchStopReason::ParsedAstNodes)
        ));
    }

    #[test]
    fn matcher_stops_at_request_wide_tag_value_budget() {
        let payload = meta_string_payload("video", 0xF1);
        let tags = vec![
            Tag::filename("example.mkv"),
            Tag::filesize(123),
            Tag::new_short(0xF1, TagValue::String("video".into())),
        ];
        let limits = RestrictiveSearchLimits {
            compared_tag_values: 2,
            ..DEFAULT_RESTRICTIVE_SEARCH_LIMITS
        };
        let search = RestrictiveSearch::parse(&payload, limits).expect("valid search");
        let mut budget = RestrictiveSearchBudget::new(limits, search.parsed_ast_nodes());

        assert_eq!(
            search.matches("example.mkv", &tags, &mut budget),
            Err(RestrictiveSearchStopReason::ComparedTagValues)
        );
        assert_eq!(budget.work().compared_tag_values, 2);
    }

    fn string_payload(value: &str) -> Vec<u8> {
        let mut payload = vec![0x01];
        payload.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
        payload.extend(value.as_bytes());
        payload
    }

    fn meta_string_payload(value: &str, name: u8) -> Vec<u8> {
        let mut payload = vec![0x02];
        payload.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
        payload.extend(value.as_bytes());
        payload.extend(1_u16.to_le_bytes());
        payload.push(name);
        payload
    }

    fn and_payload(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
        boolean_payload(0x00, left, right)
    }

    fn boolean_payload(bool_op: u8, left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
        let mut payload = vec![0x00, bool_op];
        payload.extend(left);
        payload.extend(right);
        payload
    }

    fn numeric_payload(value: u32, op: u8, name: u8) -> Vec<u8> {
        let mut payload = vec![0x03];
        payload.extend(value.to_le_bytes());
        payload.push(op);
        payload.extend(1_u16.to_le_bytes());
        payload.push(name);
        payload
    }
}
