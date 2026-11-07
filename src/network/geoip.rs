use std::net::IpAddr;
use std::sync::OnceLock;

/// Two-letter ISO country code, full name, and emoji flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountryInfo {
    pub code: &'static str,
    pub name: &'static str,
    pub flag: &'static str,
}

/// Pure-embedded GeoIP resolver using the DB-IP Lite MMDB database.
/// Supports both IPv4 and IPv6 lookups.
///
/// Uses the DB-IP Lite database (CC BY 4.0, https://db-ip.com).
pub struct GeoIpResolver;

/// The embedded DB-IP Lite country MMDB database (~7 MB).
/// License: Creative Commons Attribution 4.0 — https://db-ip.com
static GEOIP_DB: &[u8] = include_bytes!("../../data/dbip-country-lite.mmdb");

/// Lazy-initialized MMDB reader (parsed once, shared globally).
static GEOIP_READER: OnceLock<Option<maxminddb::Reader<&'static [u8]>>> = OnceLock::new();

fn get_reader() -> &'static Option<maxminddb::Reader<&'static [u8]>> {
    GEOIP_READER.get_or_init(|| {
        maxminddb::Reader::from_source(GEOIP_DB).ok()
    })
}

/// Pre-warm the GeoIP database (call from a background thread on startup).
pub fn warm() {
    let _ = get_reader();
}

// Deserialization struct matching the MMDB country record schema.
#[derive(Debug, serde::Deserialize)]
struct MmdbCountry {
    country: Option<MmdbCountryInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct MmdbCountryInfo {
    iso_code: Option<String>,
    names: Option<std::collections::HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Country metadata (code → name + flag mapping)
// ---------------------------------------------------------------------------

const fn c(code: &'static str, name: &'static str, flag: &'static str) -> CountryInfo {
    CountryInfo { code, name, flag }
}

/// Map a two-letter ISO code to our static CountryInfo.
fn country_from_code(code: &str) -> CountryInfo {
    match code {
        "US" => c("US", "United States", "\u{1f1fa}\u{1f1f8}"),
        "CA" => c("CA", "Canada", "\u{1f1e8}\u{1f1e6}"),
        "GB" => c("GB", "United Kingdom", "\u{1f1ec}\u{1f1e7}"),
        "DE" => c("DE", "Germany", "\u{1f1e9}\u{1f1ea}"),
        "FR" => c("FR", "France", "\u{1f1eb}\u{1f1f7}"),
        "NL" => c("NL", "Netherlands", "\u{1f1f3}\u{1f1f1}"),
        "JP" => c("JP", "Japan", "\u{1f1ef}\u{1f1f5}"),
        "CN" => c("CN", "China", "\u{1f1e8}\u{1f1f3}"),
        "RU" => c("RU", "Russia", "\u{1f1f7}\u{1f1fa}"),
        "IN" => c("IN", "India", "\u{1f1ee}\u{1f1f3}"),
        "BR" => c("BR", "Brazil", "\u{1f1e7}\u{1f1f7}"),
        "AU" => c("AU", "Australia", "\u{1f1e6}\u{1f1fa}"),
        "KR" => c("KR", "South Korea", "\u{1f1f0}\u{1f1f7}"),
        "SG" => c("SG", "Singapore", "\u{1f1f8}\u{1f1ec}"),
        "IE" => c("IE", "Ireland", "\u{1f1ee}\u{1f1ea}"),
        "SE" => c("SE", "Sweden", "\u{1f1f8}\u{1f1ea}"),
        "FI" => c("FI", "Finland", "\u{1f1eb}\u{1f1ee}"),
        "UA" => c("UA", "Ukraine", "\u{1f1fa}\u{1f1e6}"),
        "IL" => c("IL", "Israel", "\u{1f1ee}\u{1f1f1}"),
        "ZA" => c("ZA", "South Africa", "\u{1f1ff}\u{1f1e6}"),
        "IT" => c("IT", "Italy", "\u{1f1ee}\u{1f1f9}"),
        "ES" => c("ES", "Spain", "\u{1f1ea}\u{1f1f8}"),
        "PL" => c("PL", "Poland", "\u{1f1f5}\u{1f1f1}"),
        "CZ" => c("CZ", "Czech Republic", "\u{1f1e8}\u{1f1ff}"),
        "RO" => c("RO", "Romania", "\u{1f1f7}\u{1f1f4}"),
        "HK" => c("HK", "Hong Kong", "\u{1f1ed}\u{1f1f0}"),
        "TW" => c("TW", "Taiwan", "\u{1f1f9}\u{1f1fc}"),
        "NZ" => c("NZ", "New Zealand", "\u{1f1f3}\u{1f1ff}"),
        "CH" => c("CH", "Switzerland", "\u{1f1e8}\u{1f1ed}"),
        "AT" => c("AT", "Austria", "\u{1f1e6}\u{1f1f9}"),
        "BE" => c("BE", "Belgium", "\u{1f1e7}\u{1f1ea}"),
        "DK" => c("DK", "Denmark", "\u{1f1e9}\u{1f1f0}"),
        "NO" => c("NO", "Norway", "\u{1f1f3}\u{1f1f4}"),
        "PT" => c("PT", "Portugal", "\u{1f1f5}\u{1f1f9}"),
        "GR" => c("GR", "Greece", "\u{1f1ec}\u{1f1f7}"),
        "TR" => c("TR", "Turkey", "\u{1f1f9}\u{1f1f7}"),
        "HU" => c("HU", "Hungary", "\u{1f1ed}\u{1f1fa}"),
        "BG" => c("BG", "Bulgaria", "\u{1f1e7}\u{1f1ec}"),
        "TH" => c("TH", "Thailand", "\u{1f1f9}\u{1f1ed}"),
        "VN" => c("VN", "Vietnam", "\u{1f1fb}\u{1f1f3}"),
        "PH" => c("PH", "Philippines", "\u{1f1f5}\u{1f1ed}"),
        "MY" => c("MY", "Malaysia", "\u{1f1f2}\u{1f1fe}"),
        "ID" => c("ID", "Indonesia", "\u{1f1ee}\u{1f1e9}"),
        "AE" => c("AE", "UAE", "\u{1f1e6}\u{1f1ea}"),
        "SA" => c("SA", "Saudi Arabia", "\u{1f1f8}\u{1f1e6}"),
        "MX" => c("MX", "Mexico", "\u{1f1f2}\u{1f1fd}"),
        "AR" => c("AR", "Argentina", "\u{1f1e6}\u{1f1f7}"),
        "CO" => c("CO", "Colombia", "\u{1f1e8}\u{1f1f4}"),
        "CL" => c("CL", "Chile", "\u{1f1e8}\u{1f1f1}"),
        "EG" => c("EG", "Egypt", "\u{1f1ea}\u{1f1ec}"),
        "NG" => c("NG", "Nigeria", "\u{1f1f3}\u{1f1ec}"),
        "KE" => c("KE", "Kenya", "\u{1f1f0}\u{1f1ea}"),
        "PK" => c("PK", "Pakistan", "\u{1f1f5}\u{1f1f0}"),
        "BD" => c("BD", "Bangladesh", "\u{1f1e7}\u{1f1e9}"),
        "HR" => c("HR", "Croatia", "\u{1f1ed}\u{1f1f7}"),
        "RS" => c("RS", "Serbia", "\u{1f1f7}\u{1f1f8}"),
        "SK" => c("SK", "Slovakia", "\u{1f1f8}\u{1f1f0}"),
        "LT" => c("LT", "Lithuania", "\u{1f1f1}\u{1f1f9}"),
        "LV" => c("LV", "Latvia", "\u{1f1f1}\u{1f1fb}"),
        "EE" => c("EE", "Estonia", "\u{1f1ea}\u{1f1ea}"),
        "IS" => c("IS", "Iceland", "\u{1f1ee}\u{1f1f8}"),
        "LU" => c("LU", "Luxembourg", "\u{1f1f1}\u{1f1fa}"),
        "PE" => c("PE", "Peru", "\u{1f1f5}\u{1f1ea}"),
        "VE" => c("VE", "Venezuela", "\u{1f1fb}\u{1f1ea}"),
        "EC" => c("EC", "Ecuador", "\u{1f1ea}\u{1f1e8}"),
        "QA" => c("QA", "Qatar", "\u{1f1f6}\u{1f1e6}"),
        "KW" => c("KW", "Kuwait", "\u{1f1f0}\u{1f1fc}"),
        "BH" => c("BH", "Bahrain", "\u{1f1e7}\u{1f1ed}"),
        "OM" => c("OM", "Oman", "\u{1f1f4}\u{1f1f2}"),
        "MM" => c("MM", "Myanmar", "\u{1f1f2}\u{1f1f2}"),
        "KH" => c("KH", "Cambodia", "\u{1f1f0}\u{1f1ed}"),
        "LA" => c("LA", "Laos", "\u{1f1f1}\u{1f1e6}"),
        "NP" => c("NP", "Nepal", "\u{1f1f3}\u{1f1f5}"),
        "LK" => c("LK", "Sri Lanka", "\u{1f1f1}\u{1f1f0}"),
        "GH" => c("GH", "Ghana", "\u{1f1ec}\u{1f1ed}"),
        "TZ" => c("TZ", "Tanzania", "\u{1f1f9}\u{1f1ff}"),
        "UG" => c("UG", "Uganda", "\u{1f1fa}\u{1f1ec}"),
        "ET" => c("ET", "Ethiopia", "\u{1f1ea}\u{1f1f9}"),
        "MA" => c("MA", "Morocco", "\u{1f1f2}\u{1f1e6}"),
        "TN" => c("TN", "Tunisia", "\u{1f1f9}\u{1f1f3}"),
        "DZ" => c("DZ", "Algeria", "\u{1f1e9}\u{1f1ff}"),
        "SI" => c("SI", "Slovenia", "\u{1f1f8}\u{1f1ee}"),
        // Fallback for any other code
        other => {
            // Use a leaked static string for the code since we need 'static lifetime.
            // This is fine because country codes are finite and small.
            let code: &'static str = Box::leak(other.to_string().into_boxed_str());
            return CountryInfo { code, name: code, flag: "\u{1f310}" };
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl GeoIpResolver {
    /// Build the resolver. The MMDB is parsed lazily on first lookup
    /// (or earlier if `warm()` was called from a background thread).
    pub fn new() -> Self {
        Self
    }

    /// Look up the country for an IP address (IPv4 or IPv6).
    ///
    /// * Private / reserved ranges return `None`.
    pub fn lookup(&self, addr: IpAddr) -> Option<CountryInfo> {
        if is_private_or_reserved(addr) {
            return None;
        }

        let reader = get_reader().as_ref()?;

        let record: MmdbCountry = reader.lookup(addr).ok()?.decode().ok()??;
        let info = record.country?;
        let iso = info.iso_code?;
        if iso.is_empty() {
            return None;
        }

        let _name = info.names
            .as_ref()
            .and_then(|m| m.get("en"))
            .map(|s| s.as_str())
            .unwrap_or(&iso);

        Some(country_from_code(&iso))
    }
}

impl Default for GeoIpResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` for IPs that are private, loopback, link-local, or otherwise
/// reserved for non-public use.
fn is_private_or_reserved(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            match octets {
                [10, ..] => true,
                [172, b, ..] if b >= 16 && b <= 31 => true,
                [192, 168, ..] => true,
                [127, ..] => true,
                [169, 254, ..] => true,
                [0, ..] => true,
                [100, b, ..] if b >= 64 && b <= 127 => true,
                [192, 0, 0, _] | [192, 0, 2, _] => true,
                [198, 51, 100, _] | [203, 0, 113, _] => true,
                [198, b, ..] if b >= 18 && b <= 19 => true,
                [b, ..] if b >= 224 => true,
                _ => false,
            }
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Multicast ff00::/8
                || (v6.segments()[0] & 0xff00) == 0xff00
                // IPv4-mapped ::ffff:0:0/96 with private IPv4
                || {
                    let segs = v6.segments();
                    segs[0] == 0 && segs[1] == 0 && segs[2] == 0
                        && segs[3] == 0 && segs[4] == 0 && segs[5] == 0xffff
                        && is_private_or_reserved(IpAddr::V4(std::net::Ipv4Addr::new(
                            (segs[6] >> 8) as u8, segs[6] as u8,
                            (segs[7] >> 8) as u8, segs[7] as u8,
                        )))
                }
        }
    }
}

// ---------------------------------------------------------------------------
// Display / Debug helpers
// ---------------------------------------------------------------------------

impl std::fmt::Display for CountryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({})", self.flag, self.name, self.code)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn resolver() -> GeoIpResolver {
        GeoIpResolver::new()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn mmdb_loaded() {
        assert!(get_reader().is_some(), "MMDB database should load successfully");
    }

    #[test]
    fn private_ranges_return_none() {
        let r = resolver();
        assert!(r.lookup(v4(10, 0, 0, 1)).is_none());
        assert!(r.lookup(v4(172, 16, 0, 1)).is_none());
        assert!(r.lookup(v4(172, 31, 255, 254)).is_none());
        assert!(r.lookup(v4(192, 168, 1, 1)).is_none());
        assert!(r.lookup(v4(127, 0, 0, 1)).is_none());
        assert!(r.lookup(v4(169, 254, 1, 1)).is_none());
    }

    #[test]
    fn ipv6_loopback_returns_none() {
        let r = resolver();
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(r.lookup(addr).is_none());
    }

    #[test]
    fn google_dns() {
        let r = resolver();
        let info = r.lookup(v4(8, 8, 8, 8)).expect("should resolve 8.8.8.8");
        assert_eq!(info.code, "US");
    }

    #[test]
    fn cloudflare_dns() {
        let r = resolver();
        let info = r.lookup(v4(1, 1, 1, 1)).expect("should resolve 1.1.1.1");
        // Cloudflare anycast — could be US or AU depending on DB
        assert!(!info.code.is_empty());
    }

    #[test]
    fn hetzner_germany() {
        let r = resolver();
        let info = r.lookup(v4(136, 243, 100, 50)).expect("should resolve Hetzner");
        assert_eq!(info.code, "DE");
    }

    #[test]
    fn ovh_france() {
        let r = resolver();
        let info = r.lookup(v4(91, 121, 100, 50)).expect("should resolve OVH FR");
        assert_eq!(info.code, "FR");
    }

    #[test]
    fn china_telecom() {
        let r = resolver();
        let info = r.lookup(v4(58, 20, 10, 5)).expect("should resolve China Telecom");
        assert_eq!(info.code, "CN");
    }

    #[test]
    fn aws_tokyo() {
        let r = resolver();
        let info = r.lookup(v4(13, 112, 1, 1)).expect("should resolve AWS Tokyo");
        assert_eq!(info.code, "JP");
    }

    #[test]
    fn aws_eu_ireland() {
        let r = resolver();
        let info = r.lookup(v4(52, 48, 0, 1)).expect("should resolve AWS eu-west-1");
        assert_eq!(info.code, "IE");
    }

    #[test]
    fn ipv6_google_dns() {
        let r = resolver();
        let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        let info = r.lookup(addr).expect("should resolve Google IPv6 DNS");
        // DB-IP maps this to the actual PoP location (may be US or CA)
        assert!(!info.code.is_empty());
    }

    #[test]
    fn ipv6_cloudflare() {
        let r = resolver();
        let addr: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let info = r.lookup(addr).expect("should resolve Cloudflare IPv6");
        assert!(!info.code.is_empty());
    }

    #[test]
    fn multicast_returns_none() {
        let r = resolver();
        assert!(r.lookup(v4(224, 0, 0, 1)).is_none());
        assert!(r.lookup(v4(239, 255, 255, 255)).is_none());
    }

    #[test]
    fn carrier_grade_nat_returns_none() {
        let r = resolver();
        assert!(r.lookup(v4(100, 64, 0, 1)).is_none());
        assert!(r.lookup(v4(100, 127, 255, 254)).is_none());
    }

    #[test]
    fn country_display() {
        let info = country_from_code("US");
        let s = format!("{}", info);
        assert!(s.contains("United States"));
        assert!(s.contains("US"));
    }

    #[test]
    fn various_countries_resolve() {
        let r = resolver();
        // Test a spread of well-known IPs from different countries
        let test_cases = [
            (v4(203, 0, 113, 1), true),   // TEST-NET-3 → None (reserved)
            (v4(8, 8, 8, 8), false),        // Google DNS → should resolve
            (v4(1, 1, 1, 1), false),        // Cloudflare → should resolve
            (v4(176, 9, 0, 1), false),      // Hetzner DE → should resolve
        ];
        for (ip, expect_none) in &test_cases {
            let result = r.lookup(*ip);
            if *expect_none {
                assert!(result.is_none(), "Expected None for {}", ip);
            } else {
                assert!(result.is_some(), "Expected Some for {}", ip);
            }
        }
    }
}
