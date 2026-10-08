#include "text_analyzer.h"
#include <algorithm>
#include <cctype>
#include <vector>

namespace cyberguard {

static std::string toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

json TextAnalyzer::analyze(const std::string& text, const std::string& claimedSender) const {
    struct Finding { std::string indicator; std::string detail; int weight; };
    std::vector<Finding> findings;
    int score = 0;
    std::string lower = toLower(text);

    static const std::vector<std::string> urgencyPhrases = {
        "act now", "urgent", "immediately", "within 24 hours", "account will be suspended",
        "verify your account", "unusual activity", "your account has been locked",
        "final notice", "action required", "limited time"
    };
    int urgencyHits = 0;
    for (const auto& p : urgencyPhrases) if (lower.find(p) != std::string::npos) urgencyHits++;
    if (urgencyHits > 0) {
        int w = std::min(30, urgencyHits * 12);
        findings.push_back({ "urgency_language", std::to_string(urgencyHits) + " urgency/pressure phrase(s) detected, a hallmark of social-engineering", w });
        score += w;
    }

    static const std::vector<std::string> credentialPhrases = {
        "enter your password", "confirm your password", "otp", "one time password",
        "click here to verify", "update your payment", "card number", "cvv", "pin number",
        "social security", "aadhaar", "bank details"
    };
    int credHits = 0;
    for (const auto& p : credentialPhrases) if (lower.find(p) != std::string::npos) credHits++;
    if (credHits > 0) {
        int w = std::min(35, credHits * 15);
        findings.push_back({ "credential_request", std::to_string(credHits) + " request(s) for credentials or sensitive personal/financial data", w });
        score += w;
    }

    static const std::vector<std::string> genericGreetings = { "dear customer", "dear user", "dear valued customer", "dear account holder" };
    for (const auto& g : genericGreetings) {
        if (lower.find(g) != std::string::npos) {
            findings.push_back({ "generic_greeting", "Uses a generic greeting instead of the recipient's name, common in mass phishing campaigns", 8 });
            score += 8;
            break;
        }
    }

    bool hasLink = lower.find("http://") != std::string::npos || lower.find("https://") != std::string::npos || lower.find("www.") != std::string::npos;
    if (hasLink && (urgencyHits > 0 || credHits > 0)) {
        findings.push_back({ "link_plus_pressure", "Message combines an embedded link with urgency or credential-request language", 15 });
        score += 15;
    }

    if (!claimedSender.empty()) {
        std::string lowerSender = toLower(claimedSender);
        bool mentionsBrandButMismatched = false;
        static const std::vector<std::string> brandWords = { "bank", "paypal", "amazon", "microsoft", "google", "netflix", "irctc", "income tax" };
        for (const auto& b : brandWords) {
            if (lower.find(b) != std::string::npos && lowerSender.find(b) == std::string::npos) {
                mentionsBrandButMismatched = true;
                break;
            }
        }
        if (mentionsBrandButMismatched) {
            findings.push_back({ "sender_brand_mismatch", "Message content references a well-known brand that does not match the claimed sender identity/domain", 25 });
            score += 25;
        }
    }

    if (score > 100) score = 100;

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
        {"score", score},
        {"riskLevel", riskLevel},
        {"findings", findingsJson}
    };
}

} // namespace cyberguard
