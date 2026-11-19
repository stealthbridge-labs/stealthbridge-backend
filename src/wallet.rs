//! Classic Stellar public-account StrKey validation, with no external RPC,
//! custody, signature verification or persistence. Public G-addresses are
//! not proof of wallet ownership or permission to submit transactions.

/// Decode a checksum-valid, uppercase classic G-address to its Ed25519 public
/// key. This does not authenticate the user; a signed challenge is separate.
pub fn decode_account_address(address: &str) -> Option<[u8; 32]> {
    if address.len() != 56 || !address.starts_with('G') {
        return None;
    }
    let mut decoded = [0_u8; 35];
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut position = 0_usize;
    for b in address.bytes() {
        let digit = match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'2'..=b'7' => u32::from(b - b'2' + 26),
            _ => return None,
        };
        accumulator = (accumulator << 5) | digit;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if position >= decoded.len() {
                return None;
            }
            decoded[position] = ((accumulator >> bits) & 0xff) as u8;
            position += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    if position != decoded.len() || bits != 0 || decoded[0] != 6 << 3 {
        return None;
    }

    // Stellar StrKeys encode CRC16-XModem in little-endian order.
    let mut crc = 0_u16;
    for value in &decoded[..33] {
        crc ^= u16::from(*value) << 8;
        for _ in 0..8 {
            crc = if (crc & 0x8000) != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    if u16::from_le_bytes([decoded[33], decoded[34]]) != crc {
        return None;
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded[1..33]);
    Some(key)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StellarAddress {
    Classic([u8; 32]),
    Contract([u8; 32]),
    MuxedClassic { ed25519: [u8; 32], id: u64 },
    MuxedContract { contract: [u8; 32], id: u64 },
}

/// Official `stellar-strkey` CAP-84 / SEP-23 parser for canonical uppercase `G`, `C`, `M`, `W` strings.
pub fn parse_canonical_stellar_address(address: &str) -> Option<StellarAddress> {
    if address.len() > 69
        || !address
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    match stellar_strkey::Strkey::from_string(address).ok()? {
        stellar_strkey::Strkey::PublicKeyEd25519(k) => Some(StellarAddress::Classic(k.0)),
        stellar_strkey::Strkey::Contract(c) => Some(StellarAddress::Contract(c.0)),
        stellar_strkey::Strkey::MuxedAccountEd25519(m) => Some(StellarAddress::MuxedClassic {
            ed25519: m.ed25519,
            id: m.id,
        }),
        stellar_strkey::Strkey::MuxedContract(w) => Some(StellarAddress::MuxedContract {
            contract: w.contract_id,
            id: w.id,
        }),
        _ => None,
    }
}

/// Canonical `G...` lookup target for classic `G` or muxed `M` recipient presence checks.
pub fn resolve_classic_recipient_account(address: &str) -> Option<String> {
    match parse_canonical_stellar_address(address)? {
        StellarAddress::Classic(k) | StellarAddress::MuxedClassic { ed25519: k, .. } => Some(
            stellar_strkey::Strkey::PublicKeyEd25519(stellar_strkey::ed25519::PublicKey(k))
                .to_string()
                .as_str()
                .to_owned(),
        ),
        _ => None,
    }
}

/// Canonical `C...` lookup target for Soroban `C` or CAP-84 muxed `W` recipient presence checks.
pub fn resolve_contract_recipient(address: &str) -> Option<String> {
    match parse_canonical_stellar_address(address)? {
        StellarAddress::Contract(c) | StellarAddress::MuxedContract { contract: c, .. } => Some(
            stellar_strkey::Strkey::Contract(stellar_strkey::Contract(c))
                .to_string()
                .as_str()
                .to_owned(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const VALID: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";

    #[test]
    fn accepts_checksum_valid_classic_account() {
        let key = decode_account_address(VALID).expect("valid public address");
        let expected: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(key, expected);
    }

    #[test]
    fn rejects_invalid_checksum_and_nonaccount_strkeys() {
        for invalid in [
            "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZA",
            "CA AACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "",
        ] {
            assert!(decode_account_address(invalid).is_none());
        }
        let mut other_version = VALID.as_bytes().to_vec();
        other_version[0] = b'C';
        assert!(decode_account_address(core::str::from_utf8(&other_version).unwrap()).is_none());
    }
}
