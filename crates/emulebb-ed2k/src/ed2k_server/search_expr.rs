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

pub(super) fn encode_search_request(term: &str) -> Result<Vec<u8>> {
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
