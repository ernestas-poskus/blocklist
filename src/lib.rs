//! Blocklist is based on blocklistproject provides it perfect hash map/set
//! structures for fast lookup of blocklisted items.
#![deny(
    warnings,
    bad_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    deprecated,
    unconditional_recursion,
    unknown_lints,
    unreachable_code,
    unused_mut
)]

use fst::Set;
use once_cell::sync::Lazy;

static FST_DRUGS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-drugs.fst"));

/// Finite set machine of drugs links based on blocklistproject
pub static BLOCKLIST_DRUGS_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_DRUGS).expect("valid"));

/// Check if domain is an drugs type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_drugs(domain: &str) -> bool {
    BLOCKLIST_DRUGS_LINKS.contains(&domain)
}

static FST_ABUSE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-abuse.fst"));

/// Finite set machine of abuse links based on blocklistproject
pub static BLOCKLIST_ABUSE_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_ABUSE).expect("valid"));

/// Check if domain is an abuse type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_abuse(domain: &str) -> bool {
    BLOCKLIST_ABUSE_LINKS.contains(&domain)
}

static FST_FRAUD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-fraud.fst"));

/// Finite set machine of fraud links based on blocklistproject
pub static BLOCKLIST_FRAUD_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_FRAUD).expect("valid"));

/// Check if domain is an fraud type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_fraud(domain: &str) -> bool {
    BLOCKLIST_FRAUD_LINKS.contains(&domain)
}

static FST_GAMBLING: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-gambling.fst"));

/// Finite set machine of gambling links based on blocklistproject
pub static BLOCKLIST_GAMBLING_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_GAMBLING).expect("valid"));

/// Check if domain is an gambling type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_gambling(domain: &str) -> bool {
    BLOCKLIST_GAMBLING_LINKS.contains(&domain)
}

static FST_MALWARE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-malware.fst"));

/// Finite set machine of malware links based on blocklistproject
pub static BLOCKLIST_MALWARE_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_MALWARE).expect("valid"));

/// Check if domain is an malware type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_malware(domain: &str) -> bool {
    BLOCKLIST_MALWARE_LINKS.contains(&domain)
}

static FST_PHISHING: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-phishing.fst"));

/// Finite set machine of phishing links based on blocklistproject
pub static BLOCKLIST_PHISHING_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_PHISHING).expect("valid"));

/// Check if domain is an phishing type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_phishing(domain: &str) -> bool {
    BLOCKLIST_PHISHING_LINKS.contains(&domain)
}

static FST_PIRACY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-piracy.fst"));

/// Finite set machine of piracy links based on blocklistproject
pub static BLOCKLIST_PIRACY_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_PIRACY).expect("valid"));

/// Check if domain is an piracy type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_piracy(domain: &str) -> bool {
    BLOCKLIST_PIRACY_LINKS.contains(&domain)
}

static FST_PORN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-porn.fst"));

/// Finite set machine of porn links based on blocklistproject
pub static BLOCKLIST_PORN_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_PORN).expect("valid"));

/// Check if domain is an porn type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_porn(domain: &str) -> bool {
    BLOCKLIST_PORN_LINKS.contains(&domain)
}

static FST_RANSOMWARE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-ransomware.fst"));

/// Finite set machine of ransomware links based on blocklistproject
pub static BLOCKLIST_RANSOMWARE_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_RANSOMWARE).expect("valid"));

/// Check if domain is an ransomware type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_ransomware(domain: &str) -> bool {
    BLOCKLIST_RANSOMWARE_LINKS.contains(&domain)
}

static FST_REDIRECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-redirect.fst"));

/// Finite set machine of redirect links based on blocklistproject
pub static BLOCKLIST_REDIRECT_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_REDIRECT).expect("valid"));

/// Check if domain is an redirect type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_redirect(domain: &str) -> bool {
    BLOCKLIST_REDIRECT_LINKS.contains(&domain)
}

static FST_SCAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-scam.fst"));

/// Finite set machine of scam links based on blocklistproject
pub static BLOCKLIST_SCAM_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_SCAM).expect("valid"));

/// Check if domain is an scam type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_scam(domain: &str) -> bool {
    BLOCKLIST_SCAM_LINKS.contains(&domain)
}

static FST_TORRENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-torrent.fst"));

/// Finite set machine of torrent links based on blocklistproject
pub static BLOCKLIST_TORRENT_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_TORRENT).expect("valid"));

/// Check if domain is an torrent type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_torrent(domain: &str) -> bool {
    BLOCKLIST_TORRENT_LINKS.contains(&domain)
}

static FST_TRACKING: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-tracking.fst"));

/// Finite set machine of tracking links based on blocklistproject
pub static BLOCKLIST_TRACKING_LINKS: Lazy<Set<&[u8]>> =
    Lazy::new(|| Set::new(FST_TRACKING).expect("valid"));

/// Check if domain is an tracking type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_tracking(domain: &str) -> bool {
    BLOCKLIST_TRACKING_LINKS.contains(&domain)
}

static FST_ADS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-ads.fst"));

/// Finite set machine of ads links based on blocklistproject
pub static BLOCKLIST_ADS_LINKS: Lazy<Set<&[u8]>> = Lazy::new(|| Set::new(FST_ADS).expect("valid"));

/// Check if domain is an ads type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_advertisement(domain: &str) -> bool {
    BLOCKLIST_ADS_LINKS.contains(&domain)
}

static FST_ALL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-all.fst"));

/// Finite set machine of all links based on blocklistproject
pub static BLOCKLIST_ALL_LINKS: Lazy<Set<&[u8]>> = Lazy::new(|| Set::new(FST_ALL).expect("valid"));

/// Check if domain is an all type of link
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_everything(domain: &str) -> bool {
    BLOCKLIST_ALL_LINKS.contains(&domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_advertisement() {
        assert!(is_advertisement("000lp59.wcomhost.com"));
        assert!(is_advertisement("3003809.fls.doubleclick.net"));
        assert!(is_advertisement("mini6g.com"));
        assert!(!is_advertisement("example.com"));
    }

    #[test]
    fn test_is_drugs() {
        assert!(is_drugs("123clickcash.com"));
    }

    #[test]
    fn test_is_everything() {
        assert!(is_everything("123clickcash.com"));
        assert!(is_everything("3003809.fls.doubleclick.net"));
        assert!(!is_everything("example.com"));
    }
}
