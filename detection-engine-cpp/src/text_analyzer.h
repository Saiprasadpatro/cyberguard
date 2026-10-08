#pragma once
#include <string>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Fast, local, rule-based first pass over email/SMS/message text for phishing
// and social-engineering indicators (urgency, credential requests, generic
// greetings, sender/brand mismatch). Designed to run before/alongside the
// Gemini LLM call, per the PRD's "Hybrid Rule + AI Models" requirement:
// this engine never depends on network access and returns instantly.
class TextAnalyzer {
public:
    json analyze(const std::string& text, const std::string& claimedSender) const;
};

} // namespace cyberguard
