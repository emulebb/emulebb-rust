use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
enum SearchExprNode {
    Term(String),
    And(Box<SearchExprNode>, Box<SearchExprNode>),
    Or(Box<SearchExprNode>, Box<SearchExprNode>),
    Not(Box<SearchExprNode>, Box<SearchExprNode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SearchToken {
    Term(String),
    And,
    Or,
    Not,
    OpenParen,
    CloseParen,
}

// eD2k search metatag IDs (oracle opcodes.h) and comparison operators
// (ED2K_SEARCH_OP_*). The server filters on these when they are folded into the
// OP_SEARCHREQUEST expression tree, exactly as eMule's CSearchExprTarget emits.
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_FILEFORMAT: u8 = 0x04;
const FT_SOURCES: u8 = 0x15;
const FT_COMPLETE_SOURCES: u8 = 0x30;
const ED2K_SEARCH_OP_GREATER_EQUAL: u8 = 3;
const ED2K_SEARCH_OP_LESS_EQUAL: u8 = 4;

/// Server-side search criteria folded into the eD2k query tree (eMule
/// `GetSearchPacket`). Mirrors the constraint set eMule sends so the server
/// filters results instead of the client post-filtering a keyword-only reply.
#[derive(Debug, Default, Clone)]
pub struct SearchCriteria {
    /// eD2k file type label (e.g. "Video"/"Audio"/"Pro"); internal "Arc"/"Iso"
    /// are mapped to "Pro" on the wire like the oracle.
    pub file_type: Option<String>,
    pub extension: Option<String>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub min_availability: Option<u32>,
    pub min_complete_sources: Option<u32>,
}

impl SearchCriteria {
    fn is_empty(&self) -> bool {
        self.file_type.is_none()
            && self.extension.is_none()
            && self.min_size.is_none()
            && self.max_size.is_none()
            && self.min_availability.is_none()
            && self.min_complete_sources.is_none()
    }
}

/// Map the eMuleBB/eMule file-type label to the on-wire FT_FILETYPE string,
/// folding the internal "Arc"/"Iso" buckets to "Pro" exactly as the oracle
/// `GetSearchPacket` does (eDonkeyHybrid/filedonkey used "Pro" for both).
fn wire_file_type(file_type: &str) -> Option<String> {
    let trimmed = file_type.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(match trimmed {
        "Arc" | "Iso" => "Pro".to_string(),
        other => other.to_string(),
    })
}

pub(super) fn encode_search_request(term: &str) -> Result<Vec<u8>> {
    encode_search_request_with_criteria(term, &SearchCriteria::default())
}

/// Encode an OP_SEARCHREQUEST expression for `term` plus server-side metatag
/// constraints, as `AND(keyword, criteria...)`. Matches eMule's node encoding:
/// boolean = `00 <op>`; string = `01 <u16 len><bytes>`; string+metatag =
/// `02 <u16 len><bytes><u16 1><tagid>`; numeric+op = `03 <u32>|08 <u64> <op>
/// <u16 1><tagid>`. The keyword tree is built as before; the constraints are a
/// right-folded AND chain appended under a top-level AND.
pub(super) fn encode_search_request_with_criteria(
    term: &str,
    criteria: &SearchCriteria,
) -> Result<Vec<u8>> {
    let keyword = encode_keyword_payload(term)?;

    // Build the constraint node blobs in the oracle's order.
    let mut constraints: Vec<Vec<u8>> = Vec::new();
    if let Some(file_type) = criteria.file_type.as_deref().and_then(wire_file_type) {
        constraints.push(encode_string_meta_node(FT_FILETYPE, &file_type)?);
    }
    if let Some(min) = criteria.min_size {
        constraints.push(encode_numeric_meta_node(FT_FILESIZE, ED2K_SEARCH_OP_GREATER_EQUAL, min));
    }
    if let Some(max) = criteria.max_size {
        constraints.push(encode_numeric_meta_node(FT_FILESIZE, ED2K_SEARCH_OP_LESS_EQUAL, max));
    }
    if let Some(avail) = criteria.min_availability {
        constraints.push(encode_numeric_meta_node(
            FT_SOURCES,
            ED2K_SEARCH_OP_GREATER_EQUAL,
            u64::from(avail),
        ));
    }
    if let Some(complete) = criteria.min_complete_sources {
        constraints.push(encode_numeric_meta_node(
            FT_COMPLETE_SOURCES,
            ED2K_SEARCH_OP_GREATER_EQUAL,
            u64::from(complete),
        ));
    }
    if let Some(extension) = criteria.extension.as_deref() {
        let ext = extension.trim().trim_start_matches('.');
        if !ext.is_empty() {
            constraints.push(encode_string_meta_node(FT_FILEFORMAT, ext)?);
        }
    }

    if keyword.is_empty() {
        // No keyword (criteria-only search is not how eMule drives this); fall
        // back to the keyword payload alone (possibly empty) for safety.
        return Ok(keyword);
    }
    if criteria.is_empty() || constraints.is_empty() {
        return Ok(keyword);
    }

    // AND(keyword, <right-folded AND chain of constraints>).
    let mut payload = vec![0u8, 0x00];
    payload.extend_from_slice(&keyword);
    payload.extend_from_slice(&fold_and_chain(&constraints));
    Ok(payload)
}

/// Encode just the keyword expression bytes (no constraints).
fn encode_keyword_payload(term: &str) -> Result<Vec<u8>> {
    let Some(expression) = parse_search_expression(term)? else {
        return Ok(Vec::new());
    };
    let mut payload = Vec::new();
    if let Some(joined_terms) = flatten_and_terms(&expression) {
        encode_search_string_param(&mut payload, &joined_terms.join(" "))?;
    } else {
        encode_search_expression(&mut payload, &expression)?;
    }
    Ok(payload)
}

/// Right-fold constraint blobs into a prefix AND chain: `AND(c0, AND(c1, ...cn))`.
fn fold_and_chain(constraints: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for blob in &constraints[..constraints.len().saturating_sub(1)] {
        out.push(0u8);
        out.push(0x00);
        out.extend_from_slice(blob);
    }
    if let Some(last) = constraints.last() {
        out.extend_from_slice(last);
    }
    out
}

/// `02 <u16 len><utf8 bytes> <u16 1><tagid>` — string parameter with a 1-byte
/// metatag id (oracle `WriteMetaDataSearchParam(uMetaTagID, str)`).
fn encode_string_meta_node(meta_tag_id: u8, value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).context("ED2K search metatag string too long")?;
    let mut node = Vec::with_capacity(6 + bytes.len());
    node.push(2);
    node.extend_from_slice(&len.to_le_bytes());
    node.extend_from_slice(bytes);
    node.extend_from_slice(&1u16.to_le_bytes());
    node.push(meta_tag_id);
    Ok(node)
}

/// `03 <u32>|08 <u64> <op> <u16 1><tagid>` — numeric parameter with comparison
/// operator and a 1-byte metatag id (oracle `WriteMetaDataSearchParam(id, op,
/// value)`); emits the 64-bit form only when the value exceeds u32 (Lugdunum
/// 17.15 supports 64-bit), else the 32-bit form.
fn encode_numeric_meta_node(meta_tag_id: u8, operator: u8, value: u64) -> Vec<u8> {
    let mut node = Vec::with_capacity(9);
    if value > u64::from(u32::MAX) {
        node.push(8);
        node.extend_from_slice(&value.to_le_bytes());
    } else {
        node.push(3);
        node.extend_from_slice(&(value as u32).to_le_bytes());
    }
    node.push(operator);
    node.extend_from_slice(&1u16.to_le_bytes());
    node.push(meta_tag_id);
    node
}

fn encode_search_string_param(payload: &mut Vec<u8>, value: &str) -> Result<()> {
    let value_bytes = value.as_bytes();
    let value_len = u16::try_from(value_bytes.len()).context("ED2K search term is too long")?;
    payload.push(1);
    payload.extend_from_slice(&value_len.to_le_bytes());
    payload.extend_from_slice(value_bytes);
    Ok(())
}

fn encode_search_expression(payload: &mut Vec<u8>, expression: &SearchExprNode) -> Result<()> {
    match expression {
        SearchExprNode::Term(value) => encode_search_string_param(payload, value),
        SearchExprNode::And(left, right) => {
            payload.push(0);
            payload.push(0x00);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
        SearchExprNode::Or(left, right) => {
            payload.push(0);
            payload.push(0x01);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
        SearchExprNode::Not(left, right) => {
            payload.push(0);
            payload.push(0x02);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
    }
}

fn flatten_and_terms(expression: &SearchExprNode) -> Option<Vec<String>> {
    let mut terms = Vec::new();
    if collect_flat_and_terms(expression, &mut terms) {
        Some(terms)
    } else {
        None
    }
}

fn collect_flat_and_terms(expression: &SearchExprNode, terms: &mut Vec<String>) -> bool {
    match expression {
        SearchExprNode::Term(value) => {
            terms.push(value.clone());
            true
        }
        SearchExprNode::And(left, right) => {
            collect_flat_and_terms(left, terms) && collect_flat_and_terms(right, terms)
        }
        SearchExprNode::Or(_, _) | SearchExprNode::Not(_, _) => false,
    }
}

fn parse_search_expression(input: &str) -> Result<Option<SearchExprNode>> {
    let tokens = tokenize_search_expression(input)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut parser = SearchExpressionParser::new(tokens);
    let expression = parser.parse_expression(1)?;
    if parser.peek().is_some() {
        anyhow::bail!("unexpected trailing ED2K search tokens");
    }
    Ok(Some(expression))
}

fn tokenize_search_expression(input: &str) -> Result<Vec<SearchToken>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        match ch {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(SearchToken::OpenParen);
            }
            ')' => {
                chars.next();
                tokens.push(SearchToken::CloseParen);
            }
            '"' => {
                chars.next();
                let mut phrase = String::new();
                let mut closed = false;
                for next in chars.by_ref() {
                    if next == '"' {
                        closed = true;
                        break;
                    }
                    phrase.push(next);
                }
                if !closed {
                    anyhow::bail!("unterminated quoted ED2K search phrase");
                }
                let phrase = phrase.trim();
                if !phrase.is_empty() {
                    tokens.push(SearchToken::Term(phrase.to_string()));
                }
            }
            _ => {
                let mut word = String::new();
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || matches!(next, '(' | ')' | '"') {
                        break;
                    }
                    word.push(next);
                    chars.next();
                }
                if word.is_empty() {
                    continue;
                }
                let uppercase = word.to_ascii_uppercase();
                match uppercase.as_str() {
                    "AND" => tokens.push(SearchToken::And),
                    "OR" => tokens.push(SearchToken::Or),
                    "NOT" => tokens.push(SearchToken::Not),
                    _ => tokens.push(SearchToken::Term(word)),
                }
            }
        }
    }
    Ok(tokens)
}

struct SearchExpressionParser {
    tokens: Vec<SearchToken>,
    position: usize,
}

impl SearchExpressionParser {
    fn new(tokens: Vec<SearchToken>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn peek(&self) -> Option<&SearchToken> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<SearchToken> {
        let token = self.tokens.get(self.position).cloned()?;
        self.position += 1;
        Some(token)
    }

    fn parse_expression(&mut self, min_precedence: u8) -> Result<SearchExprNode> {
        let mut lhs = self.parse_primary()?;
        while let Some((operator, precedence, implicit)) = self.peek_binary_operator() {
            if precedence < min_precedence {
                break;
            }
            if !implicit {
                let _ = self.next();
            }
            let rhs = self.parse_expression(precedence + 1)?;
            lhs = match operator {
                SearchBinaryOperator::And => SearchExprNode::And(Box::new(lhs), Box::new(rhs)),
                SearchBinaryOperator::Or => SearchExprNode::Or(Box::new(lhs), Box::new(rhs)),
                SearchBinaryOperator::Not => SearchExprNode::Not(Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<SearchExprNode> {
        match self.next() {
            Some(SearchToken::Term(value)) => Ok(SearchExprNode::Term(value)),
            Some(SearchToken::OpenParen) => {
                let expression = self.parse_expression(1)?;
                match self.next() {
                    Some(SearchToken::CloseParen) => Ok(expression),
                    _ => anyhow::bail!("missing closing parenthesis in ED2K search expression"),
                }
            }
            Some(
                SearchToken::And | SearchToken::Or | SearchToken::Not | SearchToken::CloseParen,
            )
            | None => anyhow::bail!("invalid ED2K search expression"),
        }
    }

    fn peek_binary_operator(&self) -> Option<(SearchBinaryOperator, u8, bool)> {
        match self.peek() {
            Some(SearchToken::And) => Some((SearchBinaryOperator::And, 1, false)),
            Some(SearchToken::Or) => Some((SearchBinaryOperator::Or, 2, false)),
            Some(SearchToken::Not) => Some((SearchBinaryOperator::Not, 3, false)),
            Some(SearchToken::Term(_) | SearchToken::OpenParen) => {
                Some((SearchBinaryOperator::And, 1, true))
            }
            Some(SearchToken::CloseParen) | None => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchBinaryOperator {
    And,
    Or,
    Not,
}

#[cfg(test)]
mod criteria_tests {
    use super::*;

    fn kw(term: &str) -> Vec<u8> {
        // string param: 01 <u16 len> <bytes>
        let mut v = vec![1u8];
        v.extend_from_slice(&(term.len() as u16).to_le_bytes());
        v.extend_from_slice(term.as_bytes());
        v
    }

    #[test]
    fn empty_criteria_is_keyword_only() {
        let only_kw = encode_search_request("linux").unwrap();
        let via_criteria =
            encode_search_request_with_criteria("linux", &SearchCriteria::default()).unwrap();
        assert_eq!(only_kw, kw("linux"));
        assert_eq!(via_criteria, only_kw);
    }

    #[test]
    fn keyword_and_type_matches_oracle_node_layout() {
        let criteria = SearchCriteria {
            file_type: Some("Video".to_string()),
            ..SearchCriteria::default()
        };
        let got = encode_search_request_with_criteria("linux", &criteria).unwrap();
        // AND(00 00) + keyword + string-meta(02 <len> "Video" <01 00> <FT_FILETYPE=03>)
        let mut want = vec![0u8, 0x00];
        want.extend_from_slice(&kw("linux"));
        want.extend_from_slice(&[2, 5, 0]);
        want.extend_from_slice(b"Video");
        want.extend_from_slice(&[1, 0, FT_FILETYPE]);
        assert_eq!(got, want);
    }

    #[test]
    fn keyword_and_min_max_size_fold_as_and_chain() {
        let criteria = SearchCriteria {
            min_size: Some(1000),
            max_size: Some(2000),
            ..SearchCriteria::default()
        };
        let got = encode_search_request_with_criteria("iso", &criteria).unwrap();
        // AND(keyword, AND(minsize, maxsize))
        let mut want = vec![0u8, 0x00];
        want.extend_from_slice(&kw("iso"));
        want.extend_from_slice(&[0, 0x00]); // inner AND
        // minsize numeric: 03 <u32 1000> <op GE=3> <01 00> <FT_FILESIZE=02>
        want.push(3);
        want.extend_from_slice(&1000u32.to_le_bytes());
        want.extend_from_slice(&[ED2K_SEARCH_OP_GREATER_EQUAL, 1, 0, FT_FILESIZE]);
        // maxsize numeric: 03 <u32 2000> <op LE=4> <01 00> <FT_FILESIZE=02>
        want.push(3);
        want.extend_from_slice(&2000u32.to_le_bytes());
        want.extend_from_slice(&[ED2K_SEARCH_OP_LESS_EQUAL, 1, 0, FT_FILESIZE]);
        assert_eq!(got, want);
    }

    #[test]
    fn internal_archive_iso_types_map_to_pro() {
        assert_eq!(wire_file_type("Arc").as_deref(), Some("Pro"));
        assert_eq!(wire_file_type("Iso").as_deref(), Some("Pro"));
        assert_eq!(wire_file_type("Video").as_deref(), Some("Video"));
        assert_eq!(wire_file_type("").as_deref(), None);
    }

    #[test]
    fn large_size_uses_64bit_numeric_form() {
        let big = u64::from(u32::MAX) + 1;
        let node = encode_numeric_meta_node(FT_FILESIZE, ED2K_SEARCH_OP_GREATER_EQUAL, big);
        assert_eq!(node[0], 8, "values > u32 must use the 64-bit (0x08) numeric form");
    }
}
