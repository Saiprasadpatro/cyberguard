#include "risk_scorer.h"

namespace cyberguard {

json RiskScorer::fuse(const std::vector<json>& componentScores, const json& allFindings) const {
    double weightedSum = 0.0, weightTotal = 0.0;
    double maxComponent = 0.0;

    for (const auto& c : componentScores) {
        double score = c.value("score", 0.0);
        double weight = c.value("weight", 1.0);
        weightedSum += score * weight;
        weightTotal += weight;
        if (score > maxComponent) maxComponent = score;
    }

    double weightedAvg = weightTotal > 0 ? weightedSum / weightTotal : 0.0;
    // Final score leans toward the strongest single signal (max) while still
    // accounting for the overall weighted average, so one severe indicator
    // (e.g. a confirmed brand-lookalike domain) cannot be diluted away by
    // several low-severity ones.
    double finalScore = 0.6 * maxComponent + 0.4 * weightedAvg;
    if (finalScore > 100) finalScore = 100;

    std::string riskLevel;
    if (finalScore >= 80) riskLevel = "Critical";
    else if (finalScore >= 55) riskLevel = "High";
    else if (finalScore >= 30) riskLevel = "Medium";
    else if (finalScore >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    return json{
        {"finalScore", (int)finalScore},
        {"riskLevel", riskLevel},
        {"componentScores", componentScores},
        {"findings", allFindings}
    };
}

} // namespace cyberguard
