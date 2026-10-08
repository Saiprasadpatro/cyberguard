#pragma once
#include <string>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Result of analysing a single URL / domain for phishing & spoofing indicators.
struct UrlFinding {
    std::string indicator;
    std::string detail;
    int weight; // contribution to risk score, 0-100
};

class UrlAnalyzer {
public:
    UrlAnalyzer();

    // Analyse a raw URL string. Returns a JSON object with score, findings, riskLevel.
    json analyze(const std::string& rawUrl);

private:
    std::vector<std::string> trustedBrandDomains_;
    std::vector<std::string> suspiciousTlds_;
    std::vector<std::string> suspiciousKeywords_;

    std::string extractHost(const std::string& url) const;
    int levenshtein(const std::string& a, const std::string& b) const;
    bool hasIpHost(const std::string& host) const;
    bool hasPunycode(const std::string& host) const;
    int countHyphens(const std::string& host) const;
    int countDigits(const std::string& host) const;
    int subdomainDepth(const std::string& host) const;
};

} // namespace cyberguard
