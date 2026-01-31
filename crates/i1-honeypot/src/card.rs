//! LUHN-valid credit card generation for honeypots.

use chrono::{Datelike, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Credit card network prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CardNetwork {
    Visa,
    Mastercard,
    Amex,
    Discover,
}

impl CardNetwork {
    /// Get the IIN/BIN prefix for this network.
    fn prefix(&self) -> &str {
        match self {
            CardNetwork::Visa => "4",
            CardNetwork::Mastercard => "51",
            CardNetwork::Amex => "34",
            CardNetwork::Discover => "6011",
        }
    }

    /// Get the expected card number length.
    fn length(&self) -> usize {
        match self {
            CardNetwork::Amex => 15,
            _ => 16,
        }
    }
}

impl std::fmt::Display for CardNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardNetwork::Visa => write!(f, "Visa"),
            CardNetwork::Mastercard => write!(f, "Mastercard"),
            CardNetwork::Amex => write!(f, "American Express"),
            CardNetwork::Discover => write!(f, "Discover"),
        }
    }
}

/// A honeypot credit card that passes LUHN validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotCard {
    /// Unique identifier for tracking
    pub id: Uuid,
    /// Card network
    pub network: CardNetwork,
    /// LUHN-valid card number
    pub number: String,
    /// Expiration date (MM/YY)
    pub expiry: String,
    /// CVV/CVC
    pub cvv: String,
    /// Cardholder name
    pub holder_name: String,
    /// Formatted number for display (with spaces)
    pub display_number: String,
}

impl HoneypotCard {
    /// Generate a new honeypot card for the given network.
    pub fn generate(network: CardNetwork) -> Self {
        let number = generate_luhn_valid(network.prefix(), network.length());
        let display_number = format_card_number(&number);

        Self {
            id: Uuid::new_v4(),
            network,
            number: number.clone(),
            expiry: generate_expiry(),
            cvv: generate_cvv(network),
            holder_name: generate_holder_name(),
            display_number,
        }
    }

    /// Check if this card number is valid (for testing).
    pub fn is_valid(&self) -> bool {
        luhn_check(&self.number)
    }
}

/// Generate a LUHN-valid card number with the given prefix.
pub fn generate_luhn_valid(prefix: &str, length: usize) -> String {
    let mut rng = rand::thread_rng();

    // Start with prefix
    let mut digits: Vec<u8> = prefix.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();

    // Fill with random digits (leaving space for check digit)
    while digits.len() < length - 1 {
        digits.push(rng.gen_range(0..10));
    }

    // Calculate and append LUHN check digit
    let check_digit = calculate_luhn_check_digit(&digits);
    digits.push(check_digit);

    digits.iter().map(|d| d.to_string()).collect()
}

/// Calculate the LUHN check digit for a partial card number.
fn calculate_luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum = 0;
    let mut double = true; // Start doubling from rightmost (which will be check digit position)

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    (10 - (sum % 10)) % 10
}

/// Validate a card number using LUHN algorithm.
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u8> = number
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.is_empty() {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Format a card number with spaces for readability.
fn format_card_number(number: &str) -> String {
    if number.len() == 15 {
        // Amex: 4-6-5
        format!(
            "{} {} {}",
            &number[0..4],
            &number[4..10],
            &number[10..15]
        )
    } else {
        // Standard: 4-4-4-4
        number
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Generate a realistic expiration date (1-4 years from now).
fn generate_expiry() -> String {
    let mut rng = rand::thread_rng();
    let now = Utc::now();
    let year = now.year() + rng.gen_range(1..=4);
    let month = rng.gen_range(1..=12);
    format!("{:02}/{}", month, year % 100)
}

/// Generate a CVV/CVC code.
fn generate_cvv(network: CardNetwork) -> String {
    let mut rng = rand::thread_rng();
    let length = match network {
        CardNetwork::Amex => 4,
        _ => 3,
    };
    (0..length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}

/// Generate a realistic cardholder name.
fn generate_holder_name() -> String {
    let mut rng = rand::thread_rng();

    let first_names = [
        "JAMES", "MARY", "JOHN", "PATRICIA", "ROBERT", "JENNIFER", "MICHAEL", "LINDA",
        "WILLIAM", "ELIZABETH", "DAVID", "BARBARA", "RICHARD", "SUSAN", "JOSEPH", "JESSICA",
    ];

    let last_names = [
        "SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "GARCIA", "MILLER", "DAVIS",
        "RODRIGUEZ", "MARTINEZ", "HERNANDEZ", "LOPEZ", "GONZALEZ", "WILSON", "ANDERSON", "THOMAS",
    ];

    format!(
        "{} {}",
        first_names[rng.gen_range(0..first_names.len())],
        last_names[rng.gen_range(0..last_names.len())]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_visa() {
        let number = generate_luhn_valid("4", 16);
        assert!(luhn_check(&number), "Generated Visa number should be LUHN valid");
        assert!(number.starts_with('4'));
        assert_eq!(number.len(), 16);
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        let number = generate_luhn_valid("51", 16);
        assert!(luhn_check(&number), "Generated Mastercard number should be LUHN valid");
        assert!(number.starts_with("51"));
    }

    #[test]
    fn test_luhn_valid_amex() {
        let number = generate_luhn_valid("34", 15);
        assert!(luhn_check(&number), "Generated Amex number should be LUHN valid");
        assert!(number.starts_with("34"));
        assert_eq!(number.len(), 15);
    }

    #[test]
    fn test_known_valid_numbers() {
        // Known test card numbers
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // Mastercard test
        assert!(luhn_check("340000000000009"));  // Amex test
    }

    #[test]
    fn test_invalid_numbers() {
        assert!(!luhn_check("4111111111111112")); // Wrong check digit
        assert!(!luhn_check("1234567890123456")); // Random
    }

    #[test]
    fn test_honeypot_card_generation() {
        let card = HoneypotCard::generate(CardNetwork::Visa);
        assert!(card.is_valid());
        assert_eq!(card.network, CardNetwork::Visa);
        assert!(!card.holder_name.is_empty());
        assert!(card.cvv.len() == 3);
    }

    #[test]
    fn test_amex_has_4_digit_cvv() {
        let card = HoneypotCard::generate(CardNetwork::Amex);
        assert_eq!(card.cvv.len(), 4);
    }
}
