#pragma once
// Full URL decomposition used by both the rule-based URL analyzer and the
// URL ML model: scheme, userinfo, host, port, path, query, fragment,
// registrable domain via the Public Suffix List, punycode/IDN decoding,
// homograph skeletons and numeric-IP obfuscation detection.
#include <string>
#include <unordered_set>
#include <vector>

namespace cyberguard {

class PublicSuffixList {
public:
    bool load(const std::string& path);
    bool loaded() const { return loaded_; }
    // "a.b.example.co.uk" -> "co.uk"
    std::string publicSuffix(const std::string& host) const;
    // "a.b.example.co.uk" -> "example.co.uk" (empty if host is itself a suffix)
    std::string registrableDomain(const std::string& host) const;

    static PublicSuffixList& instance();

private:
    bool loaded_ = false;
    std::unordered_set<std::string> rules_, wildcards_, exceptions_;
};

struct ParsedUrl {
    std::string raw;
    std::string scheme;        // "" if the user typed no scheme
    std::string userinfo;      // text before '@' in the authority (a classic trick)
    std::string host;          // lowercase, as typed (may be punycode)
    std::string port;
    std::string path, query, fragment;

    std::string unicodeHost;   // punycode-decoded (UTF-8)
    std::string skeleton;      // homograph skeleton of unicodeHost (ASCII)
    bool hasPunycode = false;
    bool mixedScript = false;  // Latin mixed with Cyrillic/Greek in one label
    bool nonAsciiHost = false;

    bool isIPv4 = false, isIPv6 = false;
    bool obfuscatedIp = false; // decimal/hex/octal-encoded IPv4
    std::string normalizedIp;

    std::string publicSuffix;       // e.g. "co.in"
    std::string registrableDomain;  // e.g. "sbi.co.in"
    std::string domainLabel;        // e.g. "sbi"
    std::string subdomain;          // e.g. "secure.login"
    std::vector<std::string> queryKeys;
    bool valid = false;
};

ParsedUrl parseUrl(const std::string& url);

// RFC 3492 punycode decode of one label (without "xn--"); returns UTF-8 or "".
std::string punycodeDecode(const std::string& label);
// Maps look-alike characters (Cyrillic/Greek homoglyphs, accented Latin,
// 0/1/rn/vv tricks) onto plain ASCII so "раураl" and "paypa1" both -> "paypal".
std::string homographSkeleton(const std::string& utf8);
double shannonEntropy(const std::string& s);
std::string urlDecode(const std::string& s);

}  // namespace cyberguard
