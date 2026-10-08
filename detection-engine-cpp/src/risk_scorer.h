#pragma once
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Fuses one or more sub-engine scores (rule-based URL/text/image/anomaly
// engines, plus an optional Gemini AI confidence score) into a single
// final risk score and Safe/Low/Medium/High/Critical level, with a
// merged, de-duplicated list of contributing indicators.
class RiskScorer {
public:
    // components: list of {source, score(0-100), weight(0-1)} objects
    json fuse(const std::vector<json>& componentScores, const json& allFindings) const;
};

} // namespace cyberguard
