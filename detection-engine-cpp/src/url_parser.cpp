#include "url_parser.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <unordered_map>

namespace cyberguard {

// ------------------------------------------------------------------ PSL --
PublicSuffixList& PublicSuffixList::instance() {
    static PublicSuffixList psl;
    return psl;
}

bool PublicSuffixList::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line.rfind("//", 0) == 0) continue;
        std::string rule = line.substr(0, line.find_first_of(" \t"));
        std::transform(rule.begin(), rule.end(), rule.begin(), ::tolower);
        if (rule[0] == '!') exceptions_.insert(rule.substr(1));
        else if (rule.rfind("*.", 0) == 0) wildcards_.insert(rule.substr(2));
        else rules_.insert(rule);
    }
    loaded_ = !rules_.empty();
    return loaded_;
}

static std::vector<std::string> splitLabels(const std::string& host) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : host) {
        if (c == '.') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string joinFrom(const std::vector<std::string>& labels, size_t i) {
    std::string s;
    for (size_t k = i; k < labels.size(); ++k) { if (!s.empty()) s += "."; s += labels[k]; }
    return s;
}

std::string PublicSuffixList::publicSuffix(const std::string& host) const {
    auto labels = splitLabels(host);
    if (labels.empty()) return "";
    if (!loaded_) {
        // Fallback: common two-part suffixes, else last label.
        static const std::unordered_set<std::string> twoPart = {
            "co.in", "gov.in", "ac.in", "org.in", "net.in", "nic.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
            "com.au", "net.au", "org.au", "co.jp", "com.br", "com.cn", "co.za", "com.sg", "co.nz"};
        if (labels.size() >= 2 && twoPart.count(joinFrom(labels, labels.size() - 2)))
            return joinFrom(labels, labels.size() - 2);
        return labels.back();
    }
    for (size_t i = 0; i < labels.size(); ++i) {
        std::string cand = joinFrom(labels, i);
        if (exceptions_.count(cand)) return joinFrom(labels, i + 1);
        if (rules_.count(cand)) return cand;
        if (i + 1 < labels.size() && wildcards_.count(joinFrom(labels, i + 1))) return cand;
    }
    return labels.back();
}

std::string PublicSuffixList::registrableDomain(const std::string& host) const {
    std::string suffix = publicSuffix(host);
    if (suffix.empty() || suffix == host) return "";
    auto labels = splitLabels(host);
    auto sLabels = splitLabels(suffix);
    if (labels.size() <= sLabels.size()) return "";
    return joinFrom(labels, labels.size() - sLabels.size() - 1);
}

// ------------------------------------------------------------- helpers --
double shannonEntropy(const std::string& s) {
    if (s.empty()) return 0;
    std::map<char, int> f;
    for (char c : s) f[c]++;
    double h = 0;
    for (auto& [c, n] : f) { double p = static_cast<double>(n) / s.size(); h -= p * std::log2(p); }
    return h;
}

std::string urlDecode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            out.push_back(static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16)));
            i += 2;
        } else if (s[i] == '+') out.push_back(' ');
        else out.push_back(s[i]);
    }
    return out;
}

static void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) { out.push_back(static_cast<char>(0xC0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3F))); }
    else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

static std::vector<uint32_t> utf8ToCodepoints(const std::string& s) {
    std::vector<uint32_t> cps;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = s[i];
        uint32_t cp;
        int len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c >> 5) == 6) { cp = c & 0x1F; len = 2; }
        else if ((c >> 4) == 14) { cp = c & 0x0F; len = 3; }
        else if ((c >> 3) == 30) { cp = c & 0x07; len = 4; }
        else { ++i; continue; }
        for (int k = 1; k < len && i + k < s.size(); ++k) cp = (cp << 6) | (s[i + k] & 0x3F);
        cps.push_back(cp);
        i += len;
    }
    return cps;
}

std::string punycodeDecode(const std::string& input) {
    const uint32_t base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
    std::vector<uint32_t> output;
    size_t b = input.rfind('-');
    if (b == std::string::npos) b = 0;
    for (size_t j = 0; j < b; ++j) {
        if (static_cast<unsigned char>(input[j]) >= 0x80) return "";
        output.push_back(static_cast<unsigned char>(input[j]));
    }
    uint32_t n = initialN, i = 0, bias = initialBias;
    auto adapt = [&](uint32_t delta, uint32_t numPoints, bool first) {
        delta = first ? delta / damp : delta / 2;
        delta += delta / numPoints;
        uint32_t k = 0;
        while (delta > ((base - tmin) * tmax) / 2) { delta /= base - tmin; k += base; }
        return k + (base - tmin + 1) * delta / (delta + skew);
    };
    for (size_t in = b > 0 ? b + 1 : 0; in < input.size();) {
        uint32_t oldi = i, w = 1;
        for (uint32_t k = base;; k += base) {
            if (in >= input.size()) return "";
            char c = input[in++];
            uint32_t digit;
            if (c >= '0' && c <= '9') digit = c - '0' + 26;
            else if (c >= 'a' && c <= 'z') digit = c - 'a';
            else if (c >= 'A' && c <= 'Z') digit = c - 'A';
            else return "";
            i += digit * w;
            uint32_t t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
            if (digit < t) break;
            w *= base - t;
        }
        bias = adapt(i - oldi, static_cast<uint32_t>(output.size() + 1), oldi == 0);
        n += i / (output.size() + 1);
        i %= (output.size() + 1);
        output.insert(output.begin() + i, n);
        ++i;
    }
    std::string out;
    for (uint32_t cp : output) appendUtf8(out, cp);
    return out;
}

std::string homographSkeleton(const std::string& utf8) {
    static const std::unordered_map<uint32_t, char> map = {
        // Cyrillic
        {0x0430, 'a'}, {0x0435, 'e'}, {0x043E, 'o'}, {0x0440, 'p'}, {0x0441, 'c'}, {0x0443, 'y'},
        {0x0445, 'x'}, {0x0456, 'i'}, {0x0458, 'j'}, {0x0455, 's'}, {0x0501, 'd'}, {0x04BB, 'h'},
        {0x043A, 'k'}, {0x043C, 'm'}, {0x0442, 't'}, {0x0432, 'b'}, {0x043D, 'h'}, {0x0491, 'r'},
        {0x0410, 'a'}, {0x0415, 'e'}, {0x041E, 'o'}, {0x0420, 'p'}, {0x0421, 'c'}, {0x0425, 'x'},
        // Greek
        {0x03BF, 'o'}, {0x03B1, 'a'}, {0x03BD, 'v'}, {0x03C1, 'p'}, {0x03B9, 'i'}, {0x03BA, 'k'},
        {0x03C4, 't'}, {0x03C5, 'u'}, {0x03B5, 'e'},
        // Armenian / misc
        {0x0578, 'n'}, {0x057D, 'u'}, {0x0585, 'o'}, {0x0261, 'g'}, {0x0131, 'i'},
        // Accented Latin
        {0xE0, 'a'}, {0xE1, 'a'}, {0xE2, 'a'}, {0xE3, 'a'}, {0xE4, 'a'}, {0xE5, 'a'}, {0xE7, 'c'},
        {0xE8, 'e'}, {0xE9, 'e'}, {0xEA, 'e'}, {0xEB, 'e'}, {0xEC, 'i'}, {0xED, 'i'}, {0xEE, 'i'},
        {0xEF, 'i'}, {0xF1, 'n'}, {0xF2, 'o'}, {0xF3, 'o'}, {0xF4, 'o'}, {0xF5, 'o'}, {0xF6, 'o'},
        {0xF9, 'u'}, {0xFA, 'u'}, {0xFB, 'u'}, {0xFC, 'u'}, {0xFD, 'y'}, {0xFF, 'y'}};
    std::string s;
    for (uint32_t cp : utf8ToCodepoints(utf8)) {
        if (cp < 0x80) s.push_back(static_cast<char>(std::tolower(static_cast<int>(cp))));
        else {
            auto it = map.find(cp);
            s.push_back(it != map.end() ? it->second : '?');
        }
    }
    // ASCII look-alike tricks
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == 'r' && i + 1 < s.size() && s[i + 1] == 'n') { out.push_back('m'); ++i; }
        else if (s[i] == 'v' && i + 1 < s.size() && s[i + 1] == 'v') { out.push_back('w'); ++i; }
        else if (s[i] == '0') out.push_back('o');
        else if (s[i] == '1') out.push_back('l');
        else if (s[i] == '3') out.push_back('e');
        else if (s[i] == '5') out.push_back('s');
        else if (s[i] == '@') out.push_back('a');
        else out.push_back(s[i]);
    }
    return out;
}

static bool parseIntPart(const std::string& p, uint64_t& v) {
    if (p.empty()) return false;
    int base = 10;
    std::string s = p;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s = s.substr(2); }
    else if (s.size() > 1 && s[0] == '0') { base = 8; s = s.substr(1); }
    if (s.empty()) { v = 0; return true; }
    for (char c : s) {
        if (base == 16 && !std::isxdigit(static_cast<unsigned char>(c))) return false;
        if (base == 10 && !std::isdigit(static_cast<unsigned char>(c))) return false;
        if (base == 8 && (c < '0' || c > '7')) return false;
    }
    try { v = std::stoull(s, nullptr, base); } catch (...) { return false; }
    return true;
}

// ----------------------------------------------------------------- parse --
ParsedUrl parseUrl(const std::string& input) {
    ParsedUrl u;
    std::string s = input;
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    u.raw = s;
    if (s.empty()) return u;

    size_t schemeEnd = s.find("://");
    std::string rest = s;
    if (schemeEnd != std::string::npos && schemeEnd < 12) {
        u.scheme = s.substr(0, schemeEnd);
        std::transform(u.scheme.begin(), u.scheme.end(), u.scheme.begin(), ::tolower);
        rest = s.substr(schemeEnd + 3);
    } else if (s.rfind("//", 0) == 0) {
        rest = s.substr(2);
    }
    size_t authEnd = rest.find_first_of("/?#\\");
    std::string authority = rest.substr(0, authEnd);
    std::string tail = authEnd == std::string::npos ? "" : rest.substr(authEnd);

    size_t at = authority.rfind('@');
    if (at != std::string::npos) { u.userinfo = authority.substr(0, at); authority = authority.substr(at + 1); }

    std::string host = authority;
    if (!host.empty() && host[0] == '[') {
        size_t close = host.find(']');
        u.isIPv6 = true;
        if (close != std::string::npos) {
            if (close + 2 < host.size() && host[close + 1] == ':') u.port = host.substr(close + 2);
            host = host.substr(1, close - 1);
        }
    } else {
        size_t colon = host.rfind(':');
        if (colon != std::string::npos) { u.port = host.substr(colon + 1); host = host.substr(0, colon); }
    }
    std::transform(host.begin(), host.end(), host.begin(), ::tolower);
    while (!host.empty() && host.back() == '.') host.pop_back();
    host = urlDecode(host);
    u.host = host;

    size_t q = tail.find('?'), h = tail.find('#');
    u.path = tail.substr(0, std::min(q, h));
    if (q != std::string::npos) u.query = tail.substr(q + 1, h == std::string::npos || h < q ? std::string::npos : h - q - 1);
    if (h != std::string::npos) u.fragment = tail.substr(h + 1);
    if (!u.query.empty()) {
        std::stringstream ss(u.query);
        std::string kv;
        while (std::getline(ss, kv, '&')) {
            std::string key = kv.substr(0, kv.find('='));
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            if (!key.empty()) u.queryKeys.push_back(key);
        }
    }

    // IPv4 (plain or obfuscated decimal/hex/octal)
    if (!u.isIPv6 && !host.empty()) {
        std::vector<std::string> parts;
        std::string cur;
        for (char c : host) { if (c == '.') { parts.push_back(cur); cur.clear(); } else cur.push_back(c); }
        parts.push_back(cur);
        bool allNumeric = parts.size() <= 4;
        std::vector<uint64_t> vals;
        for (auto& p : parts) {
            uint64_t v;
            if (!parseIntPart(p, v)) { allNumeric = false; break; }
            vals.push_back(v);
        }
        if (allNumeric && !vals.empty()) {
            uint64_t ip = 0;
            bool ok = true;
            if (vals.size() == 1) ip = vals[0];
            else {
                for (size_t k = 0; k + 1 < vals.size(); ++k) { if (vals[k] > 255) ok = false; ip = (ip << 8) | vals[k]; }
                ip <<= 8 * (4 - vals.size() + 1);
                ip |= vals.back();
            }
            if (ok && ip <= 0xFFFFFFFFull) {
                u.isIPv4 = true;
                u.normalizedIp = std::to_string((ip >> 24) & 255) + "." + std::to_string((ip >> 16) & 255) + "." +
                                 std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
                u.obfuscatedIp = (u.normalizedIp != host);
            }
        }
    }

    // IDN / homographs
    std::string unicode;
    for (auto& label : splitLabels(host)) {
        std::string dec = label;
        if (label.rfind("xn--", 0) == 0) {
            u.hasPunycode = true;
            std::string d = punycodeDecode(label.substr(4));
            if (!d.empty()) dec = d;
        }
        bool latin = false, other = false;
        for (uint32_t cp : utf8ToCodepoints(dec)) {
            if ((cp >= 'a' && cp <= 'z') || (cp >= 0xC0 && cp <= 0x24F)) latin = true;
            else if ((cp >= 0x0370 && cp <= 0x03FF) || (cp >= 0x0400 && cp <= 0x052F) || (cp >= 0x0530 && cp <= 0x058F)) other = true;
            if (cp >= 0x80) u.nonAsciiHost = true;
        }
        if (latin && other) u.mixedScript = true;
        if (!unicode.empty()) unicode += ".";
        unicode += dec;
    }
    u.unicodeHost = unicode;
    u.skeleton = homographSkeleton(unicode);

    if (!u.isIPv4 && !u.isIPv6) {
        auto& psl = PublicSuffixList::instance();
        u.publicSuffix = psl.publicSuffix(host);
        u.registrableDomain = psl.registrableDomain(host);
        if (!u.registrableDomain.empty()) {
            u.domainLabel = u.registrableDomain.substr(0, u.registrableDomain.size() - u.publicSuffix.size() - 1);
            if (host.size() > u.registrableDomain.size() + 1)
                u.subdomain = host.substr(0, host.size() - u.registrableDomain.size() - 1);
        } else {
            u.domainLabel = host;
        }
    }
    u.valid = !host.empty();
    return u;
}

}  // namespace cyberguard
