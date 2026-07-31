//! Master-password policy.
//!
//! This lives in `nivrit-crypto` — not in the web client and not in the CLI —
//! because it must be identical everywhere. Under split derivation (ADR 0002)
//! the server receives a fixed-width `auth_hash` and cannot judge the password
//! behind it, so each client is the only enforcement point for its own users. If
//! the browser and the CLI disagreed, a password accepted when registering from
//! one would be rejected when changing it from the other.
//!
//! The browser reaches this through the WASM module; the CLI calls it directly.
//!
//! These rules are advisory against a determined user — anyone can call the API
//! with a hash derived from a weak password. The goal is to stop an ordinary
//! user choosing a bad password by accident, and to be honest that we cannot do
//! more.

/// Minimum accepted length. Below this we refuse outright.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Length at or above which we stop nagging.
const COMFORTABLE_LENGTH: usize = 16;

/// Passwords common enough to appear early in any cracking dictionary.
///
/// A full breach corpus is far too large to ship into a WASM module that must
/// stay small and auditable, so this is deliberately a short list of what people
/// actually type when asked to invent a password on the spot.
const OBVIOUS_PASSWORDS: &[&str] = &[
    "password",
    "passw0rd",
    "correcthorsebatterystaple",
    "administrator",
    "letmein",
    "welcome",
    "qwerty",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "trustno1",
    "changeme",
    "secret",
    "nivrit",
];

/// Coarse strength, for a meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Strong,
}

impl PasswordStrength {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordStrength::Weak => "weak",
            PasswordStrength::Fair => "fair",
            PasswordStrength::Strong => "strong",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasswordAssessment {
    /// False when the password must be rejected outright.
    pub acceptable: bool,
    pub strength: PasswordStrength,
    /// Shown to the user when there is something worth saying.
    pub message: Option<String>,
}

fn is_repeated_character(password: &str) -> bool {
    let mut chars = password.chars();
    match chars.next() {
        None => false,
        Some(first) => chars.all(|c| c == first),
    }
}

fn is_sequential(password: &str) -> bool {
    let lower = password.to_lowercase();
    if lower.chars().count() < 2 {
        return false;
    }
    ["abcdefghijklmnopqrstuvwxyz", "01234567890"]
        .iter()
        .any(|run| run.contains(&lower))
}

/// Strip everything but ASCII letters and digits, and lowercase.
fn normalize(password: &str) -> String {
    password
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Assess a candidate master password.
///
/// Length is weighted far above character-class variety on purpose: a long
/// passphrase of plain words resists offline attack better than a short string
/// with a symbol substituted in, and "one upper, one digit, one symbol" rules
/// mostly push people towards `Password1!`.
pub fn assess_password(password: &str, email: Option<&str>) -> PasswordAssessment {
    let weak = |message: &str| PasswordAssessment {
        acceptable: false,
        strength: PasswordStrength::Weak,
        message: Some(message.to_string()),
    };

    if password.is_empty() {
        return PasswordAssessment {
            acceptable: false,
            strength: PasswordStrength::Weak,
            message: None,
        };
    }

    // Count characters, not bytes: a passphrase in a non-Latin script would
    // otherwise be judged by its UTF-8 length.
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return weak(&format!(
            "Use at least {MIN_PASSWORD_LENGTH} characters. This password is the only thing protecting your secrets, and it cannot be reset for you."
        ));
    }

    let normalized = normalize(password);

    if OBVIOUS_PASSWORDS.contains(&normalized.as_str()) {
        return weak(
            "This is one of the first passwords an attacker will try. Choose something else.",
        );
    }

    if is_repeated_character(password) || is_sequential(password) {
        return weak("Repeated or sequential characters are trivial to guess.");
    }

    if let Some(email) = email {
        let local_part: String = email
            .split('@')
            .next()
            .unwrap_or_default()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if local_part.chars().count() >= 3 && normalized.contains(&local_part) {
            return weak("Do not build your password out of your email address.");
        }
    }

    if password.chars().count() < COMFORTABLE_LENGTH {
        return PasswordAssessment {
            acceptable: true,
            strength: PasswordStrength::Fair,
            message: Some(
                "Accepted. A longer passphrase of a few unrelated words would be stronger.".into(),
            ),
        };
    }

    PasswordAssessment {
        acceptable: true,
        strength: PasswordStrength::Strong,
        message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_passwords() {
        assert!(!assess_password("short", None).acceptable);
        assert!(!assess_password(&"a".repeat(MIN_PASSWORD_LENGTH - 1), None).acceptable);
    }

    #[test]
    fn rejects_obvious_passwords_even_when_long_enough() {
        assert!(!assess_password("correcthorsebatterystaple", None).acceptable);
        assert!(!assess_password("administrator", None).acceptable);
    }

    #[test]
    fn ignores_punctuation_and_case_when_matching() {
        assert!(!assess_password("Administrator!", None).acceptable);
    }

    #[test]
    fn rejects_repeated_and_sequential() {
        assert!(!assess_password("aaaaaaaaaaaaaaaa", None).acceptable);
        assert!(!assess_password("abcdefghijklmnop", None).acceptable);
    }

    #[test]
    fn rejects_password_built_from_the_email() {
        assert!(!assess_password("jsmith-and-more-text", Some("jsmith@example.com")).acceptable);
    }

    #[test]
    fn tolerates_a_very_short_email_local_part() {
        // A two-character local part would otherwise match almost anything.
        assert!(assess_password("a-perfectly-fine-passphrase", Some("ab@example.com")).acceptable);
    }

    #[test]
    fn accepts_a_long_passphrase() {
        let result = assess_password("ferry unicorn glacier tuesday", None); // codeql[rust/hard-coded-cryptographic-value]
        assert!(result.acceptable);
        assert_eq!(result.strength, PasswordStrength::Strong);
    }

    #[test]
    fn accepts_but_nudges_an_adequate_password() {
        let result = assess_password("sp1nach-wagon", None); // codeql[rust/hard-coded-cryptographic-value]
        assert!(result.acceptable);
        assert_eq!(result.strength, PasswordStrength::Fair);
        assert!(result.message.is_some());
    }

    #[test]
    fn empty_password_has_no_scolding_message() {
        let result = assess_password("", None); // codeql[rust/hard-coded-cryptographic-value]
        assert!(!result.acceptable);
        assert!(result.message.is_none());
    }

    #[test]
    fn counts_characters_not_bytes() {
        // Twelve multi-byte characters is twelve characters.
        let passphrase = "パスワードパスワードパス";
        assert_eq!(passphrase.chars().count(), 12);
        assert!(assess_password(passphrase, None).acceptable);
    }
}

#[cfg(test)]
mod e2e_fixture_tests {
    use super::*;

    /// The web e2e suite registers with these values; if the policy ever
    /// rejects them the suite fails in a confusing place, so assert it here.
    #[test]
    fn e2e_fixture_password_satisfies_policy() {
        for email in ["alice-web-abc123@example.com", "bob-web-abc123@example.com"] {
            let assessment = assess_password("web-test-glacier-tuesday", Some(email)); // codeql[rust/hard-coded-cryptographic-value]
            assert!(
                assessment.acceptable,
                "e2e fixture password rejected for {email}: {:?}",
                assessment.message
            );
        }
    }
}
