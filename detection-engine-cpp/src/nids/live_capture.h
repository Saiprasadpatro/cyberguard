#pragma once
// Live packet capture for the NIDS (libpcap). Compiled in when the engine is
// built with CG_WITH_PCAP (the Docker image does this). A capture thread
// buffers packets; every `analysisInterval` seconds the last `windowSeconds`
// of traffic is re-analysed and new alerts are kept (and optionally POSTed
// to the backend when running as a stand-alone sensor).
#include <string>

#include "json.hpp"

namespace cyberguard::nids {

using json = nlohmann::json;

struct LiveOptions {
    std::string iface;
    std::string bpf;               // e.g. "not port 5050"
    int windowSeconds = 120;
    int analysisInterval = 10;
    std::string reportUrl;         // e.g. http://localhost:4000/api/nids/ingest (sensor mode)
    std::string reportKey;         // sent as x-engine-key
    std::string sensorName = "cyberguard-sensor";
};

class LiveCapture {
public:
    static LiveCapture& instance();
    static bool supported();
    json interfaces() const;
    json start(const LiveOptions& opt);
    json stop();
    json status() const;

private:
    LiveCapture() = default;
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace cyberguard::nids
