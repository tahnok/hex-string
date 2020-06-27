//! A utilty library for handling Hex strings
//!
//! The digest operations in sha2 return the result as u8 vectors. But a lot of command line
//! applicaions, like sha256sum, return byte strings. I was unable to find an obvious way to handle
//! this in rust, so this module provides a clear well-defined HexString, loaders from a regular
//! string of hex values and from a vector of bytes, and output representations in both forms.

use std::collections::{ HashSet };
use std::result;
use std::str::FromStr;

/// HexString provides a structured representation of a hex string. It is guaranteed to be a valid
/// string, whether initialized from a string or from a byte vector.
#[derive(Clone, Debug, PartialEq)]
pub struct HexString(String);

#[derive(thiserror::Error, Debug)]
pub enum HexStringError {
    /// There was an invalid character in the hex string
    #[error("Encountered invalid character: '{0}'")]
    InvalidCharacter(char),

    /// All hex strings must be an even length in order to represent bytes because each two
    /// characters represents one byte
    #[error("String length was odd, but it must be even")]
    InvalidStringLength,

    /// Somehow the conversion function tried to convert a value outside the range of 0-15
    /// (inclusive) into a hex value. This should only be raised from a direct call to
    /// `nibble_to_hexchar`, or in the case of a bug in this module.
    #[error("Weird error, tried to convert nible outside of 0-15(inclusive), byte value '{0}'")]
    InvalidNibble(u8),
}

type Result<A> = result::Result<A, HexStringError>;


/// Given a character, convert it into a u8 in the range 0-15 (inclusive).
///
/// Note that Rust does not have an obvious nibble data type, so we approximate with the lower 4
/// bits of a u8.
///
/// This will raise InvalidCharacte if the provided character is not in the range 0-9 or a-f
/// (lower-case only).
pub fn hexchar_to_nibble(c: &char) -> Result<u8> {
    match c {
        '0' => Ok(0),
        '1' => Ok(1),
        '2' => Ok(2),
        '3' => Ok(3),
        '4' => Ok(4),
        '5' => Ok(5),
        '6' => Ok(6),
        '7' => Ok(7),
        '8' => Ok(8),
        '9' => Ok(9),
        'a' => Ok(10),
        'b' => Ok(11),
        'c' => Ok(12),
        'd' => Ok(13),
        'e' => Ok(14),
        'f' => Ok(15),
        _ => Err(HexStringError::InvalidCharacter(*c))
    }
}


/// Given a nibble (a u8 value in the range 0-15), convert it to its corresponding character
/// representation.
///
/// This will raise InvalidNibble if the value provided is outside the range 0-15.
pub fn nibble_to_hexchar(b: &u8) -> Result<char>  {
    match b {
        0 => Ok('0'),
        1 => Ok('1'),
        2 => Ok('2'),
        3 => Ok('3'),
        4 => Ok('4'),
        5 => Ok('5'),
        6 => Ok('6'),
        7 => Ok('7'),
        8 => Ok('8'),
        9 => Ok('9'),
        10 => Ok('a'),
        11 => Ok('b'),
        12 => Ok('c'),
        13 => Ok('d'),
        14 => Ok('e'),
        15 => Ok('f'),
        _ => Err(HexStringError::InvalidNibble(*b)),
    }
}


/// Convert a byte to its two-character hex string representation
pub fn u8_to_hex_string(b: &u8) -> [char; 2] {
    fn fmt_error(b: &u8) -> String {
        format!("should never have an invalid nibble here. parts: {:?}, {:?}", (b & 0xf0) >> 4, b & 0x0f)
    }
    let upper = nibble_to_hexchar(&((b & 0xf0) >> 4)).expect(&fmt_error(b));
    let lower = nibble_to_hexchar(&(b & 0x0f)).expect(&fmt_error(b));
    [upper, lower]
}


impl HexString {
    /// Initialize a HexString from an actual hex string. The input string must be of an even
    /// length (since it takes two hex characters to represent a byte) and must contain only
    /// characters in the range 0-9 and a-f.
    ///
    /// This will return an InvalidStringLength error if the length is not even, and
    /// InvalidCharacter if any non-hex character is detected.
    pub fn from_string(s: &str) -> Result<HexString> {
        if s.len() % 2 != 0 { return Err(HexStringError::InvalidStringLength) }

        let mut valid_chars = HashSet::new();
        valid_chars.insert('0');
        valid_chars.insert('1');
        valid_chars.insert('2');
        valid_chars.insert('3');
        valid_chars.insert('4');
        valid_chars.insert('5');
        valid_chars.insert('6');
        valid_chars.insert('7');
        valid_chars.insert('8');
        valid_chars.insert('9');
        valid_chars.insert('a');
        valid_chars.insert('b');
        valid_chars.insert('c');
        valid_chars.insert('d');
        valid_chars.insert('e');
        valid_chars.insert('f');

        for c in s.chars() {
            if ! valid_chars.contains(&c) {
                return Err(HexStringError::InvalidCharacter(c));
            }
        }
        Ok(HexString(String::from(s)))
    }

    /// Initialize a hex string from a binary vector. This function cannot fail.
    pub fn from_bytes(v: &[u8]) -> HexString {
        HexString(v.iter().map(|b| u8_to_hex_string(b)).fold(String::new(), |mut acc, s| {
            acc.push(s[0]);
            acc.push(s[1]);
            acc
        }))
    }

    /// Return a String representation
    pub fn as_string(&self) -> String {
        self.0.clone()
    }

    /// Return a &str slice
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Return a byte representation
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut i = self.0.chars();
        let mut octets: Vec<Vec<char>> = Vec::new();

        let mut octet: Vec<char> = i.by_ref().take(2).collect();
        while octet.len() != 0 {
            octets.push(octet.clone());
            octet = i.by_ref().take(2).collect();
        }

        fn to_byte(octet: Vec<char>) -> u8 {
            let upper = hexchar_to_nibble(&octet[0]).expect("There should never be an invalid hexchar here");
            let lower = hexchar_to_nibble(&octet[1]).expect("There should never be an invalid hexchar here");
            (upper << 4) | lower
        }

        octets.into_iter().map(|octet| to_byte(octet)).collect()
    }
}

/// Implementing the FromStr trait will let it be combined better with other crates
/// It refers the implementation to the existing `from_string` function.
impl FromStr for HexString {
    type Err = HexStringError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_string(s)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn byte_repr() -> Vec<u8> { vec![203, 187, 198, 225, 155, 230, 62, 252, 221, 120, 50, 125, 45, 248, 80, 217, 35, 117, 175, 106, 3, 147, 79, 53, 228, 123, 208, 45, 27, 73, 108, 12] }
    fn string_repr() -> String { String::from("cbbbc6e19be63efcdd78327d2df850d92375af6a03934f35e47bd02d1b496c0c") }

    #[test]
    fn it_converts_bytes_to_string() {
        let res = HexString::from_bytes(&byte_repr());
        assert_eq!(*res.as_string(), string_repr());
    }

    #[test]
    fn it_converts_bytes_to_str_slice() {
        let res = HexString::from_bytes(&byte_repr());
        assert_eq!(res.as_str(), string_repr());
    }

    #[test]
    fn it_converts_string_to_bytes() {
        match HexString::from_string(&string_repr()) {
            Err(err) => panic!(format!("error encoding from string: {:?}", err)),
            Ok(res) => assert_eq!(res.as_bytes(), byte_repr()),
        }
    }

    #[test]
    fn it_rejects_invalid_strings() {
        match HexString::from_string("abcdefg") {
            Err(_err) => (),
            Ok(_) => panic!("did not reject a 'g' in the string"),
        }
    }

    #[test]
    fn it_can_be_parsed_using_the_parse_function() {
        let _hex_s = string_repr().parse::<HexString>()
            .expect("string_repr example should be parsable");
    }

    #[test]
    fn it_can_fail_for_uneven_length_strings_using_the_parse_function() {
        let hex_s = "abb".parse::<HexString>();
        assert!(hex_s.is_err())
    }
}
