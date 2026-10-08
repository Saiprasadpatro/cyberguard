#include "url_analyzer.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <set>

#include "brands.h"
#include "url_parser.h"

namespace cyberguard {

UrlAnalyzer::UrlAnalyzer() {
    // Reference set of well-known brand domains commonly impersonated.
    // In production this should be loaded from the scans DB / threat-intel feed
    // instead of hardcoded; kept inline here so the engine has zero external
    // dependencies and works out of the box.
    trustedBrandDomains_ = {
        "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
        "facebook.com", "instagram.com", "netflix.com", "sbi.co.in", "hdfcbank.com",
        "icicibank.com", "irctc.co.in", "incometax.gov.in", "uidai.gov.in",
        "github.com", "linkedin.com", "whatsapp.com"
    };
    suspiciousTlds_ = { "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "work", "click", "loan" };
    suspiciousKeywords_ = { "login", "verify", "update", "secure", "account", "confirm",
                             "signin", "banking", "webscr", "reset", "unlock", "suspend" };
}

std::string UrlAnalyzer::extractHost(const std::string& url) const {
    std::string s = url;
    // strip scheme
    auto schemePos = s.find("://");
    if (schemePos != std::string::npos) s = s.substr(schemePos + 3);
    // strip path/query
    auto slashPos = s.find_first_of("/?#");
    if (slashPos != std::string::npos) s = s.substr(0, slashPos);
    // strip credentials
    auto atPos = s.find('@');
    if (atPos != std::string::npos) s = s.substr(atPos + 1);
    // strip port
    auto colonPos = s.find(':');
    if (colonPos != std::string::npos) s = s.substr(0, colonPos);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

int UrlAnalyzer::levenshtein(const std::string& a, const std::string& b) const {
    const size_t n = a.size(), m = b.size();
    std::vector<std::vector<int>> dp(n + 1, std::vector<int>(m + 1));
    for (size_t i = 0; i <= n; i++) dp[i][0] = static_cast<int>(i);
    for (size_t j = 0; j <= m; j++) dp[0][j] = static_cast<int>(j);
    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= m; j++) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            dp[i][j] = std::min({ dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost });
        }
    }
    return dp[n][m];
}

bool UrlAnalyzer::hasIpHost(const std::string& host) const {
    static const std::regex ipRe(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    return std::regex_match(host, ipRe);
}

bool UrlAnalyzer::hasPunycode(const std::string& host) const {
    return host.find("xn--") != std::string::npos;
}

int UrlAnalyzer::countHyphens(const std::string& host) const {
    return static_cast<int>(std::count(host.begin(), host.end(), '-'));
}

int UrlAnalyzer::countDigits(const std::string& host) const {
    return static_cast<int>(std::count_if(host.begin(), host.end(), [](unsigned char c) { return std::isdigit(c); }));
}

int UrlAnalyzer::subdomainDepth(const std::string& host) const {
    return static_cast<int>(std::count(host.begin(), host.end(), '.'));
}

json UrlAnalyzer::analyze(const std::string& rawUrl) {
    std::string host = extractHost(rawUrl);
    std::vector<UrlFinding> findings;
    int score = 0;

    if (host.empty()) {
        return json{ {"score", 0}, {"riskLevel", "Safe"}, {"findings", json::array()}, {"host", host} };
    }

    if (hasIpHost(host)) {
        findings.push_back({ "ip_literal_host", "URL uses a raw IP address instead of a domain name", 25 });
        score += 25;
    }

    if (hasPunycode(host)) {
        findings.push_back({ "punycode_domain", "Domain uses punycode (xn--), often used to spoof lookalike characters", 25 });
        score += 25;
    }

    if (countHyphens(host) >= 3) {
        findings.push_back({ "excessive_hyphens", "Domain contains an unusually high number of hyphens", 10 });
        score += 10;
    }

    if (countDigits(host) >= 4) {
        findings.push_back({ "excessive_digits", "Domain contains an unusually high number of digits", 8 });
        score += 8;
    }

    if (subdomainDepth(host) >= 4) {
        findings.push_back({ "deep_subdomain", "Excessive subdomain nesting, a common cloaking technique", 12 });
        score += 12;
    }

    // Extract registrable-ish domain (last two labels) for TLD + brand comparison
    std::string tld;
    {
        auto lastDot = host.find_last_of('.');
        if (lastDot != std::string::npos) tld = host.substr(lastDot + 1);
    }
    if (std::find(suspiciousTlds_.begin(), suspiciousTlds_.end(), tld) != suspiciousTlds_.end()) {
        findings.push_back({ "suspicious_tld", "Domain uses a top-level domain frequently abused for phishing (." + tld + ")", 15 });
        score += 15;
    }

    for (const auto& kw : suspiciousKeywords_) {
        if (host.find(kw) != std::string::npos) {
            findings.push_back({ "credential_keyword_in_domain", "Domain contains a credential-related keyword (\"" + kw + "\") often used to imitate legitimate login flows", 12 });
            score += 12;
            break;
        }
    }

    // Brand impersonation via edit-distance to known trusted domains (typosquatting / lookalike detection)
    std::string closestBrand;
    int closestDist = 9999;
    for (const auto& brand : trustedBrandDomains_) {
        if (host == brand) { closestDist = 0; closestBrand = brand; break; }
        int d = levenshtein(host, brand);
        if (d < closestDist) { closestDist = d; closestBrand = brand; }
    }
    if (closestDist > 0 && closestDist <= 2 && !closestBrand.empty()) {
        findings.push_back({ "brand_lookalike", "Domain is a close lookalike of a known trusted domain (\"" + closestBrand + "\", edit distance " + std::to_string(closestDist) + ")", 35 });
        score += 35;
    }

    // ------------------------------------------------------------------
    // Deep structural analysis (full URL parse + Public Suffix List).
    // HTTPS is deliberately NOT treated as a trust signal: most phishing
    // sites now have free, valid certificates.
    // ------------------------------------------------------------------
    ParsedUrl u = parseUrl(rawUrl.find("://") == std::string::npos ? "http://" + rawUrl : rawUrl);
    bool official = isOfficialBrandDomain(u.registrableDomain);
    auto add = [&](const std::string& ind, const std::string& detail, int w) {
        for (auto& f : findings) if (f.indicator == ind) return;
        findings.push_back({ind, detail, w});
        score += w;
    };
    if (rawUrl.find("://") != std::string::npos && u.scheme == "http")
        add("no_tls", "Link uses plain http:// - anything typed into this page travels unencrypted", 8);
    if (u.scheme == "https")
        add("https_is_not_trust", "Link uses https:// - this only means the connection is encrypted, NOT that the site is genuine (most phishing sites use free certificates)", 0);
    if (!u.userinfo.empty())
        add("userinfo_at_trick", "URL contains an '@': everything before it (\"" + u.userinfo.substr(0, 60) + "\") is ignored by the browser, which really opens " + u.host, 30);
    if (u.obfuscatedIp)
        add("obfuscated_ip_host", "Host \"" + u.host + "\" is an encoded IP address (really " + u.normalizedIp + "), a trick to hide the destination", 35);
    if (u.hasPunycode || u.nonAsciiHost) {
        bool brandSkeleton = false;
        std::string matched;
        std::string skelLabel = homographSkeleton(u.domainLabel.empty() ? u.unicodeHost : u.unicodeHost.substr(0, u.unicodeHost.find('.')));
        for (auto& b : knownBrands())
            if (b.name.size() >= 4 && (u.skeleton.find(b.name) != std::string::npos)) { brandSkeleton = true; matched = b.name; break; }
        if (brandSkeleton && !official)
            add("homograph_brand_spoof", "Internationalised domain \"" + u.unicodeHost + "\" uses look-alike characters to imitate \"" + matched + "\"", 45);
        else if (u.mixedScript)
            add("mixed_script_domain", "Domain mixes Latin with Cyrillic/Greek characters (\"" + u.unicodeHost + "\"), a homograph technique", 25);
        else
            add("internationalised_domain", "Domain uses non-ASCII characters (\"" + u.unicodeHost + "\")", 5);
    }
    if (!official && !u.registrableDomain.empty()) {
        std::string lowerPath = u.path + "?" + u.query;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
        for (auto& b : knownBrands()) {
            if (b.name.size() < 4) continue;
            if (u.subdomain.find(b.name) != std::string::npos) {
                add("brand_in_subdomain", "\"" + b.name + "\" appears in the subdomain, but the real registered domain is \"" + u.registrableDomain + "\" (not owned by " + b.name + ")", 30);
                break;
            }
            if (homographSkeleton(u.domainLabel) != u.domainLabel && homographSkeleton(u.domainLabel) == b.name) {
                add("homograph_brand_spoof", "Domain \"" + u.registrableDomain + "\" swaps look-alike characters to imitate \"" + b.name + "\"", 45);
                break;
            }
            if (u.domainLabel.find(b.name) != std::string::npos) {
                add("brand_in_domain_not_official", "Domain \"" + u.registrableDomain + "\" contains \"" + b.name + "\" but is not one of " + b.name + "'s official domains", 25);
                break;
            }
            if (lowerPath.find(b.name) != std::string::npos) {
                add("brand_in_path", "\"" + b.name + "\" appears in the link path while the site itself is \"" + u.registrableDomain + "\"", 15);
                break;
            }
        }
    }
    if (!u.port.empty() && u.port != "80" && u.port != "443")
        add("nonstandard_port", "Uses non-standard port " + u.port, 10);
    for (auto& k : u.queryKeys)
        for (auto r : {"url", "redirect", "redirect_uri", "redir", "next", "returnurl", "goto", "dest", "destination", "continue", "target"})
            if (k == r && (u.query.find("http") != std::string::npos || u.query.find("%2f%2f") != std::string::npos || u.query.find("%2F%2F") != std::string::npos))
                add("open_redirect_parameter", "Query parameter \"" + k + "=\" carries another URL - a common way to bounce victims through a trusted site", 15);
    {
        std::string lp = u.path;
        std::transform(lp.begin(), lp.end(), lp.begin(), ::tolower);
        for (auto e : {".exe", ".apk", ".scr", ".msi", ".bat", ".jar", ".vbs", ".iso", ".js", ".hta", ".lnk"})
            if (lp.size() >= std::strlen(e) && lp.compare(lp.size() - std::strlen(e), std::strlen(e), e) == 0)
                add("executable_download", "Link points directly to an executable/script file (" + std::string(e) + ")", 25);
        if (lp.find("//") != std::string::npos) add("double_slash_path", "Path contains '//' (often used for redirects or path confusion)", 5);
        for (auto t : {".com/", ".net/", ".org/", ".co.in", "www."})
            if (lp.find(t) != std::string::npos) { add("domain_in_path", "Path contains what looks like another domain (\"" + std::string(t) + "\") to make the link look legitimate", 10); break; }
    }
    static const std::set<std::string> shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id", "bitly.com", "v.gd", "qr.ae"};
    if (shorteners.count(u.registrableDomain) || shorteners.count(u.host))
        add("url_shortener", "Shortened link hides the real destination (the live check expands it)", 10);
    static const std::set<std::string> freeHosting = {"web.app", "firebaseapp.com", "glitch.me", "ngrok.io", "ngrok-free.app", "weebly.com", "000webhostapp.com",
                                                      "azurefd.net", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com", "repl.co",
                                                      "wixsite.com", "blogspot.com", "github.io", "gitbook.io", "sites.google.com", "square.site", "godaddysites.com",
                                                      "web.core.windows.net", "appspot.com", "r2.dev", "firebasestorage.googleapis.com", "ipfs.io", "duckdns.org"};
    bool freeHost = freeHosting.count(u.registrableDomain) || freeHosting.count(u.publicSuffix);
    for (auto& fh : freeHosting) if (u.host.size() > fh.size() && u.host.compare(u.host.size() - fh.size(), fh.size(), fh) == 0) freeHost = true;
    if (freeHost) {
        bool lure = false;
        for (auto& kw : suspiciousKeywords_) if (rawUrl.find(kw) != std::string::npos) lure = true;
        for (auto& b : knownBrands()) if (b.name.size() >= 4 && rawUrl.find(b.name) != std::string::npos) lure = true;
        add(lure ? "free_hosting_with_lure" : "free_hosting_platform",
            lure ? "Hosted on a free/anyone-can-publish platform (" + u.host + ") while using brand or login wording - a very common phishing setup"
                 : "Hosted on a free/anyone-can-publish platform (" + u.host + ")",
            lure ? 25 : 5);
    }
    size_t pct = std::count(rawUrl.begin(), rawUrl.end(), '%');
    if (pct >= 6) add("heavy_url_encoding", std::to_string(pct) + " percent-encoded characters obscure what the link contains", 10);
    if (rawUrl.size() > 150) add("very_long_url", "Unusually long URL (" + std::to_string(rawUrl.size()) + " characters), often used to push the real domain out of view", 5);
    if (official) add("verified_brand_domain", "Registered domain \"" + u.registrableDomain + "\" is an official domain of a known brand", 0);

    if (score > 100) score = 100;
    if (official && score > 0) {
        // Official brand domains: only structural tricks (userinfo, encoded IP) keep a high score.
        bool structural = !u.userinfo.empty() || u.obfuscatedIp;
        if (!structural) score = std::min(score, 15);
    }

    std::string riskLevel;
    if (score >= 80) riskLevel = "Critical";
    else if (score >= 55) riskLevel = "High";
    else if (score >= 30) riskLevel = "Medium";
    else if (score >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    json findingsJson = json::array();
    for (const auto& f : findings) {
        findingsJson.push_back({ {"indicator", f.indicator}, {"detail", f.detail}, {"weight", f.weight} });
    }

    return json{
        {"host", host},
        {"score", score},
        {"riskLevel", riskLevel},
        {"findings", findingsJson},
        {"trustedBrandDomain", official},
        {"anatomy", {
            {"scheme", u.scheme}, {"userinfo", u.userinfo}, {"host", u.host}, {"unicodeHost", u.unicodeHost},
            {"homographSkeleton", u.skeleton}, {"port", u.port}, {"path", u.path}, {"query", u.query},
            {"queryKeys", u.queryKeys}, {"registrableDomain", u.registrableDomain}, {"publicSuffix", u.publicSuffix},
            {"subdomain", u.subdomain}, {"isIp", u.isIPv4 || u.isIPv6}, {"normalizedIp", u.normalizedIp},
            {"punycode", u.hasPunycode}, {"mixedScript", u.mixedScript}}}
    };
}

} // namespace cyberguard
