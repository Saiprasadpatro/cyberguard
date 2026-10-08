#pragma once
// CyberGuard Network Intrusion Detection System.
//
//   packets -> connection tracking (Zeek-style TCP states) -> KDD traffic
//   features -> ML (GBDT + Random Forest + Isolation Forest) + signature
//   rules (scans, floods, DNS tunnelling, beaconing, brute force, ...)
//   -> alerts with severity, evidence and MITRE ATT&CK mapping.
#include <string>
#include <vector>

#include "json.hpp"
#include "packet.h"

namespace cyberguard::nids {

using json = nlohmann::json;

struct NidsOptions {
    double idleTimeout = 60.0;
    size_t maxFlows = 300000;
    size_t maxFlowsInReport = 150;
};

json analyzePackets(const std::vector<RawPacket>& packets, const std::string& sourceLabel,
                    const NidsOptions& opt = NidsOptions());

// Convenience for uploaded capture files.
json analyzeCaptureBytes(const std::string& bytes, const std::string& sourceLabel);

bool isPrivateIp(const std::string& ip);

}  // namespace cyberguard::nids
