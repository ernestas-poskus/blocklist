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
    deprecated,
    unknown_lints,
    unreachable_code,
    unused_mut,
    unreachable_pub
)]

#[cfg(any(
    feature = "abuse",
    feature = "drugs",
    feature = "fraud",
    feature = "gambling",
    feature = "malware",
    feature = "phishing",
    feature = "piracy",
    feature = "porn",
    feature = "ransomware",
    feature = "redirect",
    feature = "scam",
    feature = "torrent",
    feature = "tracking",
    feature = "ads",
    feature = "everything"
))]
use fst::Set;
#[cfg(any(
    feature = "abuse",
    feature = "drugs",
    feature = "fraud",
    feature = "gambling",
    feature = "malware",
    feature = "phishing",
    feature = "piracy",
    feature = "porn",
    feature = "ransomware",
    feature = "redirect",
    feature = "scam",
    feature = "torrent",
    feature = "tracking",
    feature = "ads",
    feature = "everything"
))]
use once_cell::sync::Lazy;

macro_rules! define_blocklist {
    ($feature:literal, $fst:ident, $links:ident, $fn_name:ident, $name:literal) => {
        #[cfg(feature = $feature)]
        static $fst: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-", $name, ".fst"));

        #[cfg(feature = $feature)]
        #[doc = "Finite set machine of "]
        #[doc = $name]
        #[doc = " links based on blocklistproject"]
        pub static $links: Lazy<Set<&[u8]>> = Lazy::new(|| Set::new($fst).expect("valid"));

        #[cfg(feature = $feature)]
        #[doc = "Check if domain is a "]
        #[doc = $name]
        #[doc = " type of link"]
        ///
        /// Note that parsing domain is not a part of this crate
        /// you should use some other crate for that, e.g.: URL.
        pub fn $fn_name(domain: &str) -> bool {
            $links.contains(&domain)
        }
    };
}

define_blocklist!("abuse", FST_ABUSE, BLOCKLIST_ABUSE_LINKS, is_abuse, "abuse");
define_blocklist!("drugs", FST_DRUGS, BLOCKLIST_DRUGS_LINKS, is_drugs, "drugs");
define_blocklist!("fraud", FST_FRAUD, BLOCKLIST_FRAUD_LINKS, is_fraud, "fraud");
define_blocklist!(
    "gambling",
    FST_GAMBLING,
    BLOCKLIST_GAMBLING_LINKS,
    is_gambling,
    "gambling"
);
define_blocklist!(
    "malware",
    FST_MALWARE,
    BLOCKLIST_MALWARE_LINKS,
    is_malware,
    "malware"
);
define_blocklist!(
    "phishing",
    FST_PHISHING,
    BLOCKLIST_PHISHING_LINKS,
    is_phishing,
    "phishing"
);
define_blocklist!(
    "piracy",
    FST_PIRACY,
    BLOCKLIST_PIRACY_LINKS,
    is_piracy,
    "piracy"
);
define_blocklist!("porn", FST_PORN, BLOCKLIST_PORN_LINKS, is_porn, "porn");
define_blocklist!(
    "ransomware",
    FST_RANSOMWARE,
    BLOCKLIST_RANSOMWARE_LINKS,
    is_ransomware,
    "ransomware"
);
define_blocklist!(
    "redirect",
    FST_REDIRECT,
    BLOCKLIST_REDIRECT_LINKS,
    is_redirect,
    "redirect"
);
define_blocklist!("scam", FST_SCAM, BLOCKLIST_SCAM_LINKS, is_scam, "scam");
define_blocklist!(
    "torrent",
    FST_TORRENT,
    BLOCKLIST_TORRENT_LINKS,
    is_torrent,
    "torrent"
);
define_blocklist!(
    "tracking",
    FST_TRACKING,
    BLOCKLIST_TRACKING_LINKS,
    is_tracking,
    "tracking"
);
define_blocklist!("ads", FST_ADS, BLOCKLIST_ADS_LINKS, is_advertisement, "ads");

#[cfg(feature = "everything")]
static FST_ALL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist-all.fst"));

#[cfg(feature = "everything")]
/// Finite set machine of all enabled blocklists based on blocklistproject
pub static BLOCKLIST_ALL_LINKS: Lazy<Set<&[u8]>> = Lazy::new(|| Set::new(FST_ALL).expect("valid"));

#[cfg(feature = "everything")]
/// Check if domain is in all enabled blocklist types
///
/// Note that parsing domain is not a part of this crate
/// you should use some other crate for that, e.g.: URL.
pub fn is_everything(domain: &str) -> bool {
    BLOCKLIST_ALL_LINKS.contains(&domain)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ads")]
    #[test]
    fn test_is_advertisement() {
        assert!(super::is_advertisement("000lp59.wcomhost.com"));
        assert!(super::is_advertisement("3003809.fls.doubleclick.net"));
        assert!(super::is_advertisement("mini6g.com"));
        assert!(!super::is_advertisement("example.com"));
    }

    #[cfg(feature = "drugs")]
    #[test]
    fn test_is_drugs() {
        assert!(super::is_drugs("123clickcash.com"));
    }

    #[cfg(feature = "everything")]
    #[test]
    fn test_is_everything() {
        assert!(super::is_everything("123clickcash.com"));
        assert!(super::is_everything("3003809.fls.doubleclick.net"));
        assert!(!super::is_everything("example.com"));
    }
}
