use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
enum Comparison {
    Equal(u64),
    Greater(u64),
    GreaterOrEqual(u64),
    Less(u64),
    LessOrEqual(u64),
}

#[derive(Debug, Clone)]
enum Matcher {
    Text { value: String, case_sensitive: bool },
    Regex(Regex),
    Number(Comparison),
}

#[derive(Debug, Clone)]
struct Term {
    field: Option<String>,
    negated: bool,
    matcher: Matcher,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FilterQuery {
    terms: Vec<Term>,
    pub(crate) all_scope: bool,
}

impl FilterQuery {
    pub(crate) fn parse(
        input: &str,
        allowed_fields: &[&str],
        numeric_fields: &[&str],
    ) -> Result<Self, String> {
        let mut query = Self::default();
        for mut token in tokenize(input)? {
            if token == "@all" {
                query.all_scope = true;
                continue;
            }
            let negated = token.starts_with('!');
            if negated {
                token.remove(0);
            }
            if token.is_empty() {
                return Err("negation requires a value".into());
            }

            let (field, value) = if let Some(pattern) = token.strip_prefix("re:") {
                (None, format!("re:{}", pattern))
            } else if let Some((candidate, value)) = token.split_once(':') {
                if allowed_fields.contains(&candidate) {
                    (Some(candidate.to_string()), value.to_string())
                } else if candidate
                    .chars()
                    .all(|character| character.is_ascii_alphabetic() || character == '_')
                {
                    return Err(format!("unknown field '{candidate}'"));
                } else {
                    (None, token)
                }
            } else {
                (None, token)
            };
            if value.is_empty() {
                return Err(format!(
                    "{} requires a value",
                    field.as_deref().unwrap_or("term")
                ));
            }

            let matcher = if let Some(pattern) = value.strip_prefix("re:") {
                if pattern.is_empty() {
                    return Err("regular expression cannot be empty".into());
                }
                let case_sensitive = pattern.chars().any(char::is_uppercase);
                Matcher::Regex(
                    RegexBuilder::new(pattern)
                        .case_insensitive(!case_sensitive)
                        .build()
                        .map_err(|error| format!("invalid regex: {error}"))?,
                )
            } else if field
                .as_deref()
                .is_some_and(|name| numeric_fields.contains(&name))
                && starts_comparison(&value)
            {
                Matcher::Number(parse_comparison(&value)?)
            } else {
                Matcher::Text {
                    case_sensitive: value.chars().any(char::is_uppercase),
                    value,
                }
            };
            query.terms.push(Term {
                field,
                negated,
                matcher,
            });
        }
        Ok(query)
    }

    pub(crate) fn matches(&self, fields: &[(&str, String)]) -> bool {
        self.terms.iter().all(|term| {
            let matched = fields
                .iter()
                .filter(|(name, _)| term.field.as_deref().is_none_or(|field| field == *name))
                .any(|(_, value)| term.matcher.matches(value));
            if term.negated {
                !matched
            } else {
                matched
            }
        })
    }
}

impl Matcher {
    fn matches(&self, candidate: &str) -> bool {
        match self {
            Self::Text {
                value,
                case_sensitive,
            } => {
                // nft prints sets with spaces (`{1812, 1813}`), while filters are
                // usually entered compactly (`port:1812,1813`). Ignore whitespace
                // when a term looks like a comma-separated value list.
                let (candidate, value) = if value.contains(',') {
                    (
                        candidate
                            .chars()
                            .filter(|character| !character.is_whitespace())
                            .collect::<String>(),
                        value
                            .chars()
                            .filter(|character| !character.is_whitespace())
                            .collect::<String>(),
                    )
                } else {
                    (candidate.to_string(), value.to_string())
                };
                if *case_sensitive {
                    candidate.contains(&value)
                } else {
                    candidate.to_lowercase().contains(&value.to_lowercase())
                }
            }
            Self::Regex(regex) => regex.is_match(candidate),
            Self::Number(comparison) => candidate
                .trim()
                .parse::<u64>()
                .is_ok_and(|number| comparison.matches(number)),
        }
    }
}

impl Comparison {
    fn matches(&self, candidate: u64) -> bool {
        match self {
            Self::Equal(value) => candidate == *value,
            Self::Greater(value) => candidate > *value,
            Self::GreaterOrEqual(value) => candidate >= *value,
            Self::Less(value) => candidate < *value,
            Self::LessOrEqual(value) => candidate <= *value,
        }
    }
}

fn starts_comparison(value: &str) -> bool {
    value.starts_with(['=', '>', '<'])
}

fn parse_comparison(value: &str) -> Result<Comparison, String> {
    let (operator, number) = if let Some(number) = value.strip_prefix(">=") {
        (">=", number)
    } else if let Some(number) = value.strip_prefix("<=") {
        ("<=", number)
    } else if let Some(number) = value.strip_prefix('>') {
        (">", number)
    } else if let Some(number) = value.strip_prefix('<') {
        ("<", number)
    } else if let Some(number) = value.strip_prefix('=') {
        ("=", number)
    } else {
        ("=", value)
    };
    let number = parse_number(number.trim())?;
    Ok(match operator {
        ">" => Comparison::Greater(number),
        ">=" => Comparison::GreaterOrEqual(number),
        "<" => Comparison::Less(number),
        "<=" => Comparison::LessOrEqual(number),
        _ => Comparison::Equal(number),
    })
}

fn parse_number(value: &str) -> Result<u64, String> {
    let (number, multiplier) = match value.chars().last() {
        Some('k' | 'K') => (&value[..value.len() - 1], 1_000),
        Some('m' | 'M') => (&value[..value.len() - 1], 1_000_000),
        Some('g' | 'G') => (&value[..value.len() - 1], 1_000_000_000),
        _ => (value, 1),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .ok_or_else(|| format!("invalid numeric comparison '{value}'"))
}

fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if quoted {
        return Err("unclosed quote".into());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: &[&str] = &["proto", "port", "comment", "packets"];
    const NUMERIC: &[&str] = &["packets"];

    fn fields() -> Vec<(&'static str, String)> {
        vec![
            ("proto", "udp".into()),
            ("port", "1812, 1813".into()),
            ("comment", "Allow RADIUS Auth".into()),
            ("packets", "1200".into()),
        ]
    }

    #[test]
    fn combines_fields_quotes_and_negation() {
        let query = FilterQuery::parse(
            "proto:udp port:1812,1813 comment:\"RADIUS Auth\" !comment:deny",
            FIELDS,
            NUMERIC,
        )
        .unwrap();
        assert!(query.matches(&fields()));
    }

    #[test]
    fn supports_smart_case_regex_and_numeric_suffixes() {
        assert!(
            FilterQuery::parse("re:radius packets:>=1k", FIELDS, NUMERIC)
                .unwrap()
                .matches(&fields())
        );
        assert!(
            !FilterQuery::parse("re:radius packets:>2k", FIELDS, NUMERIC)
                .unwrap()
                .matches(&fields())
        );
        assert!(!FilterQuery::parse("RADIUSauth", FIELDS, NUMERIC)
            .unwrap()
            .matches(&fields()));
    }

    #[test]
    fn reports_invalid_queries() {
        assert!(FilterQuery::parse("wat:value", FIELDS, NUMERIC).is_err());
        assert!(FilterQuery::parse("re:[", FIELDS, NUMERIC).is_err());
        assert!(FilterQuery::parse("comment:\"open", FIELDS, NUMERIC).is_err());
    }
}
