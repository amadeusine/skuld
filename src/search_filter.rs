use crate::protocol_types::{self as pt, search};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::{
        complete::{alpha1, char as ch, digit0, digit1},
        is_hex_digit,
    },
    combinator::{opt, recognize},
    multi::{many0, many1},
    sequence::{terminated, tuple},
    IResult, InputTakeAtPosition,
};

const LPAREN: char = '(';
const RPAREN: char = ')';
const AMPERSAND: char = '&';
const VERTBAR: char = '|';
const EXCLAMATION: char = '!';
const TILDE: char = '~';
const RANGLE: char = '>';
const LANGLE: char = '<';
const ASTERISK: char = '*';
const EQUALS: char = '=';
const COLON: char = ':';
const ESC: char = '\\';
const DOT: char = '.';
const HYPHEN: char = '-';

pub(crate) fn parse_search_string(s: &str) -> Result<search::Filter, Box<dyn std::error::Error>> {
    Ok(filter(s).map(|(_, filter)| filter).map_err(|_| "bad search filter")?)
}

/// filter         = LPAREN filtercomp RPAREN
fn filter(s: &str) -> IResult<&str, search::Filter> {
    tuple((ch(LPAREN), filtercomp, ch(RPAREN)))(s).map(|t| (t.0, (t.1).1))
}

/// filtercomp     = and / or / not / item
fn filtercomp(s: &str) -> IResult<&str, search::Filter> {
    alt((and, or, not, item))(s)
}

/// and            = AMPERSAND filterlist
fn and(s: &str) -> IResult<&str, search::Filter> {
    let (s, (_, filters)) = tuple((ch(AMPERSAND), filter_list))(s)?;

    Ok((s, search::Filter::And(filters)))
}

/// or             = VERTBAR filterlist
fn or(s: &str) -> IResult<&str, search::Filter> {
    let (s, (_, filters)) = tuple((ch(VERTBAR), filter_list))(s)?;

    Ok((s, search::Filter::Or(filters)))
}

/// not            = EXCLAMATION filter
fn not(s: &str) -> IResult<&str, search::Filter> {
    let (s, (_, filter)) = tuple((ch(EXCLAMATION), filter))(s)?;

    Ok((s, search::Filter::Not(Box::new(filter))))
}

/// filterlist     = 1*filter
fn filter_list(s: &str) -> IResult<&str, Vec<search::Filter>> {
    many1(filter)(s)
}

/// item           = simple / present / substring / extensible
fn item(s: &str) -> IResult<&str, search::Filter> {
    alt((present, substring, simple, extensible))(s)
}

/// simple         = attr filtertype assertionvalue
fn simple(s: &str) -> IResult<&str, search::Filter> {
    let (s, (attr_desc, filter_type, assertion_value)) =
        tuple((attribute_description, filtertype, assertion_value))(s)?;

    let attr_value_assertion = pt::AttributeValueAssertion {
        attribute_description: pt::AttributeDescription(attr_desc.to_string()),
        assertion_value: assertion_value.to_string(),
    };

    match filter_type {
        FilterType::Equal => Ok((s, search::Filter::EqualityMatch(attr_value_assertion))),
        FilterType::GreaterOrEqual => Ok((s, search::Filter::GreaterOrEqual(attr_value_assertion))),
        FilterType::LessOrEqual => Ok((s, search::Filter::LessOrEqual(attr_value_assertion))),
        FilterType::Approx => Ok((s, search::Filter::ApproximateMatch(attr_value_assertion))),
    }
}

/// present        = attr EQUALS ASTERISK
fn present(s: &str) -> IResult<&str, search::Filter> {
    let (s, (attr_desc, _, _)) = tuple((attr, ch(EQUALS), ch(ASTERISK)))(s)?;
    Ok((s, search::Filter::Present(pt::AttributeDescription(attr_desc.to_string()))))
}

/// substring      = attr EQUALS [initial] any [final]
fn substring(s: &str) -> IResult<&str, search::Filter> {
    let (s, (attr_desc, _, initial, any_substrings, fin)) =
        tuple((attr, ch(EQUALS), opt(assertion_value), any_substring, opt(assertion_value)))(s)?;

    Ok((
        s,
        search::Filter::Substrings(search::SubstringFilter {
            r#type: pt::AttributeDescription(attr_desc.to_string()),
            substrings: match (initial, fin) {
                (Some(initial), None) | (Some(initial), Some("")) => {
                    let mut v = vec![search::Substring::Initial(initial.to_string())];
                    v.extend(
                        any_substrings.into_iter().map(|s| search::Substring::Any(s.to_string())),
                    );

                    v
                }
                (Some(initial), Some(fin)) => {
                    let mut v = vec![search::Substring::Initial(initial.to_string())];
                    v.extend(
                        any_substrings.into_iter().map(|s| search::Substring::Any(s.to_string())),
                    );
                    v.push(search::Substring::Final(fin.to_string()));

                    v
                }
                (None, Some(fin)) => {
                    let mut v = vec![];
                    v.extend(
                        any_substrings.into_iter().map(|s| search::Substring::Any(s.to_string())),
                    );
                    v.push(search::Substring::Final(fin.to_string()));

                    v
                }
                (None, None) => any_substrings
                    .into_iter()
                    .map(|s| search::Substring::Any(s.to_string()))
                    .collect(),
            },
        }),
    ))
}

/// any            = ASTERISK *(assertionvalue ASTERISK)
fn any_substring(s: &str) -> IResult<&str, Vec<&str>> {
    let (s, (_, substrs)) =
        tuple((ch(ASTERISK), many0(terminated(assertion_value, ch(ASTERISK)))))(s)?;

    Ok((s, substrs))
}

fn extensible(s: &str) -> IResult<&str, search::Filter> {
    todo!("extensible search parsing")
}

enum FilterType {
    Equal,
    Approx,
    GreaterOrEqual,
    LessOrEqual,
}

/// filtertype     = equal / approx / greaterorequal / lessorequal
fn filtertype(s: &str) -> IResult<&str, FilterType> {
    alt((equal, approx, greater_or_equal, less_or_equal))(s)
}

fn equal(s: &str) -> IResult<&str, FilterType> {
    let (s, _) = ch(EQUALS)(s)?;

    Ok((s, FilterType::Equal))
}

fn approx(s: &str) -> IResult<&str, FilterType> {
    let (s, _) = tuple((ch(TILDE), ch(EQUALS)))(s)?;

    Ok((s, FilterType::Approx))
}

fn greater_or_equal(s: &str) -> IResult<&str, FilterType> {
    let (s, _) = tuple((ch(RANGLE), ch(EQUALS)))(s)?;

    Ok((s, FilterType::GreaterOrEqual))
}

fn less_or_equal(s: &str) -> IResult<&str, FilterType> {
    let (s, _) = tuple((ch(LANGLE), ch(EQUALS)))(s)?;

    Ok((s, FilterType::LessOrEqual))
}

/// attr           = attributedescription
#[inline(always)]
fn attr(s: &str) -> IResult<&str, &str> {
    attribute_description(s)
}

/// attributedescription = attributetype options
/// attributetype = oid
/// options = *( SEMI option )
/// option = 1*keychar
fn attribute_description(s: &str) -> IResult<&str, &str> {
    let keychar = alt((alpha1, digit1, tag("-")));
    let options = many0(tuple((tag(";"), many1(keychar))));
    recognize(tuple((oid, options)))(s)
}

/// assertionvalue = valueencoding
#[inline(always)]
fn assertion_value(s: &str) -> IResult<&str, &str> {
    value_encoding(s)
}

/// valueencoding  = 0*(normal / escaped)
fn value_encoding(s: &str) -> IResult<&str, &str> {
    let utf_subset = is_not("\u{0}()*\\");
    let escaped = recognize(tuple((ch('\\'), two_hex_digits)));
    recognize(many0(alt((utf_subset, escaped))))(s)
}

/// oid = descr / numericoid
/// descr = keystring
fn oid(s: &str) -> IResult<&str, &str> {
    alt((keystring, numericoid))(s)
}

/// numericoid = number 1*( DOT number )
fn numericoid(s: &str) -> IResult<&str, &str> {
    let dot_number = many1(tuple((ch(DOT), number)));

    let number_dot_number = tuple((number, dot_number));

    recognize(number_dot_number)(s)
}

/// number  = DIGIT / ( LDIGIT 1*DIGIT )
fn number(s: &str) -> IResult<&str, &str> {
    recognize(tuple((nonzero_digit1, digit0)))(s)
}

/// keystring = leadkeychar *keychar
/// leadkeychar = ALPHA
/// keychar = ALPHA / DIGIT / HYPHEN
fn keystring(s: &str) -> IResult<&str, &str> {
    let keychar = alt((alpha1, digit1, tag("-")));

    let keystring = tuple((alpha1, many0(keychar)));

    recognize(keystring)(s)
}

fn nonzero_digit1<T, E: nom::error::ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition,
    <T as InputTakeAtPosition>::Item: nom::AsChar,
{
    use nom::AsChar;
    input.split_at_position1_complete(
        |item| !matches!(item.as_char(), '1'..='9'),
        nom::error::ErrorKind::Digit,
    )
}

fn two_hex_digits(s: &str) -> IResult<&str, &str> {
    match s.get(..2) {
        Some(s2) if s2.chars().all(|c| is_hex_digit(c as u8)) => Ok((&s[2..], s2)),
        None => Err(nom::Err::Incomplete(nom::Needed::Unknown)),
        _ => Err(nom::Err::Failure((s, nom::error::ErrorKind::Digit))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! s {
        () => {{
            String::new()
        }};
        ($s:literal) => {{
            $s.to_string()
        }};
    }

    #[test]
    fn simples() {
        let filter = "(cn=Babs Jensen)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::EqualityMatch(pt::AttributeValueAssertion {
                attribute_description: pt::AttributeDescription(s!("cn")),
                assertion_value: s!("Babs Jensen"),
            })
        );

        let filter = "(!(cn=Babs Jensen))";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::Not(Box::new(search::Filter::EqualityMatch(
                pt::AttributeValueAssertion {
                    attribute_description: pt::AttributeDescription(s!("cn")),
                    assertion_value: s!("Babs Jensen"),
                }
            )))
        );

        let filter = "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::And(vec![
                search::Filter::EqualityMatch(pt::AttributeValueAssertion {
                    attribute_description: pt::AttributeDescription(s!("objectClass")),
                    assertion_value: s!("Person"),
                }),
                search::Filter::Or(vec![
                    search::Filter::EqualityMatch(pt::AttributeValueAssertion {
                        attribute_description: pt::AttributeDescription(s!("sn")),
                        assertion_value: s!("Jensen"),
                    }),
                    search::Filter::Substrings(search::SubstringFilter {
                        r#type: pt::AttributeDescription(s!("cn")),
                        substrings: vec![search::Substring::Initial(s!("Babs J"))],
                    })
                ])
            ])
        );

        let filter = "(o=univ*of*mich*)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::Substrings(search::SubstringFilter {
                r#type: pt::AttributeDescription(s!("o")),
                substrings: vec![
                    search::Substring::Initial(s!("univ")),
                    search::Substring::Any(s!("of")),
                    search::Substring::Any(s!("mich"))
                ],
            })
        );

        let filter = "(o=univ*of*mich*n)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::Substrings(search::SubstringFilter {
                r#type: pt::AttributeDescription(s!("o")),
                substrings: vec![
                    search::Substring::Initial(s!("univ")),
                    search::Substring::Any(s!("of")),
                    search::Substring::Any(s!("mich")),
                    search::Substring::Final(s!("n")),
                ],
            })
        );

        let filter = "(seeAlso=)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::EqualityMatch(pt::AttributeValueAssertion {
                attribute_description: pt::AttributeDescription(s!("seeAlso")),
                assertion_value: s!(),
            })
        );

        let filter = "(cn~=Potato)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::ApproximateMatch(pt::AttributeValueAssertion {
                attribute_description: pt::AttributeDescription(s!("cn")),
                assertion_value: s!("Potato"),
            })
        );

        let filter = "(count>=1)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::GreaterOrEqual(pt::AttributeValueAssertion {
                attribute_description: pt::AttributeDescription(s!("count")),
                assertion_value: s!("1"),
            })
        );

        let filter = "(count<=1)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::LessOrEqual(pt::AttributeValueAssertion {
                attribute_description: pt::AttributeDescription(s!("count")),
                assertion_value: s!("1"),
            })
        );

        let filter = "(cn=*)";
        assert_eq!(
            parse_search_string(filter).unwrap(),
            search::Filter::Present(pt::AttributeDescription(s!("cn")))
        );
    }
}
