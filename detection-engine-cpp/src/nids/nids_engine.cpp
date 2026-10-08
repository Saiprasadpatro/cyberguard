#include "nids_engine.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <map>
#include <numeric>
#include <tuple>
#include <set>
#include <unordered_map>

#include "../features/nids_features.h"
#include "../model_registry.h"
#include "../url_parser.h"

namespace cyberguard::nids {

bool isPrivateIp(const std::string& ip) {
    if (ip.find(':') != std::string::npos) return ip.rfind("fe80", 0) == 0 || ip.rfind("fc", 0) == 0 || ip.rfind("fd", 0) == 0 || ip == "::1";
    int a = 0, b = 0;
    if (std::sscanf(ip.c_str(), "%d.%d", &a, &b) != 2) return false;
    return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127);
}

namespace {

struct Flow {
    std::string proto, origIp, respIp;
    uint16_t origPort = 0, respPort = 0;
    double start = 0, last = 0;
    uint64_t origBytes = 0, respBytes = 0, origPkts = 0, respPkts = 0;
    bool synOrig = false, synAckResp = false, finOrig = false, finResp = false, rstOrig = false, rstResp = false;
    bool firstWasSyn = false, closed = false, dataSeen = false;
    int urgent = 0, badFrag = 0, icmpType = -1;
    std::vector<std::string> dnsQueries;
};

std::string connFlag(const Flow& f) {
    if (f.proto != "tcp") return "SF";
    if (!f.firstWasSyn) return "OTH";
    if (!f.synAckResp) {
        if (f.rstOrig) return "RSTOS0";
        if (f.rstResp) return "REJ";
        if (f.finOrig) return "SH";
        return "S0";
    }
    if (f.rstOrig) return "RSTO";
    if (f.rstResp) return "RSTR";
    if (f.finOrig && f.finResp) return "SF";
    if (f.finOrig) return "S2";
    if (f.finResp) return "S3";
    return "S1";
}

json mitre(std::initializer_list<std::pair<const char*, const char*>> t) {
    json a = json::array();
    for (auto& [id, name] : t) a.push_back({{"id", id}, {"name", name}});
    return a;
}

int sevRank(const std::string& s) {
    if (s == "Critical") return 4;
    if (s == "High") return 3;
    if (s == "Medium") return 2;
    if (s == "Low") return 1;
    return 0;
}

}  // namespace

json analyzePackets(const std::vector<RawPacket>& packets, const std::string& sourceLabel, const NidsOptions& opt) {
    std::vector<Flow> flows;
    std::unordered_map<std::string, size_t> active;
    std::map<std::string, uint64_t> protoCount;
    std::map<std::string, uint64_t> talkerBytes;
    uint64_t decoded = 0, totalBytes = 0;
    double tMin = 1e300, tMax = 0;
    struct DnsQ { double ts; std::string src, name; };
    std::vector<DnsQ> dnsQs;

    for (const auto& rp : packets) {
        DecodedPacket p = decodePacket(rp);
        if (!p.valid) continue;
        decoded++;
        totalBytes += p.wireLen;
        tMin = std::min(tMin, p.ts);
        tMax = std::max(tMax, p.ts);
        protoCount[p.proto]++;
        talkerBytes[p.src] += p.wireLen;
        if (!p.dnsQuery.empty()) dnsQs.push_back({p.ts, p.src, p.dnsQuery});
        if (p.proto == "other") continue;

        // Canonical unordered key.
        uint16_t sp = p.sport, dp = p.dport;
        if (p.proto == "icmp") sp = dp = p.icmpId;
        std::string a = p.src + ":" + std::to_string(sp), b = p.dst + ":" + std::to_string(dp);
        std::string key = p.proto + "|" + (a < b ? a + "|" + b : b + "|" + a);
        auto it = active.find(key);
        bool newFlow = it == active.end();
        if (!newFlow) {
            Flow& f = flows[it->second];
            bool isSyn = p.proto == "tcp" && (p.tcpFlags & 0x02) && !(p.tcpFlags & 0x10);
            if (p.ts - f.last > opt.idleTimeout || (f.closed && isSyn)) newFlow = true;
        }
        if (newFlow) {
            if (flows.size() >= opt.maxFlows) continue;
            Flow f;
            f.proto = p.proto;
            f.origIp = p.src; f.respIp = p.dst; f.origPort = p.sport; f.respPort = p.dport;
            // ICMP replies seen first: orient on the request direction
            if (p.proto == "icmp") {
                f.icmpType = p.icmpType;
                if (p.icmpType == 0) { std::swap(f.origIp, f.respIp); f.icmpType = 8; }
                f.origPort = f.respPort = 0;
            }
            if (p.proto == "tcp") {
                bool syn = (p.tcpFlags & 0x02) && !(p.tcpFlags & 0x10);
                bool synAck = (p.tcpFlags & 0x12) == 0x12;
                if (synAck) { std::swap(f.origIp, f.respIp); std::swap(f.origPort, f.respPort); }
                f.firstWasSyn = syn || synAck;
            }
            f.start = f.last = p.ts;
            flows.push_back(f);
            active[key] = flows.size() - 1;
            it = active.find(key);
        }
        Flow& f = flows[it->second];
        bool fromOrig = (p.src == f.origIp && (p.proto == "icmp" || p.sport == f.origPort));
        f.last = p.ts;
        if (fromOrig) { f.origBytes += p.payloadLen; f.origPkts++; } else { f.respBytes += p.payloadLen; f.respPkts++; }
        if (p.badFragment) f.badFrag++;
        if (!p.dnsQuery.empty() && f.dnsQueries.size() < 5) f.dnsQueries.push_back(p.dnsQuery);
        if (p.proto == "tcp") {
            uint8_t fl = p.tcpFlags;
            if (fl & 0x20) f.urgent++;
            if (fromOrig) {
                if ((fl & 0x02) && !(fl & 0x10)) f.synOrig = true;
                if (fl & 0x01) f.finOrig = true;
                if (fl & 0x04) f.rstOrig = true;
            } else {
                if ((fl & 0x12) == 0x12) f.synAckResp = true;
                if (fl & 0x01) f.finResp = true;
                if (fl & 0x04) f.rstResp = true;
            }
            if (p.payloadLen) f.dataSeen = true;
            if ((f.finOrig && f.finResp) || f.rstOrig || f.rstResp) f.closed = true;
        }
    }

    // ---- connection records + traffic features
    std::vector<features::ConnRecord> conns;
    conns.reserve(flows.size());
    for (size_t i = 0; i < flows.size(); ++i) {
        const Flow& f = flows[i];
        features::ConnRecord c;
        c.tag = static_cast<long>(i);
        c.startTime = f.start;
        c.duration = std::max(0.0, f.last - f.start);
        c.protocol = f.proto;
        c.service = features::kddService(f.proto, f.respPort, f.icmpType);
        c.flag = connFlag(f);
        c.srcIp = f.origIp; c.dstIp = f.respIp; c.srcPort = f.origPort; c.dstPort = f.respPort;
        c.srcBytes = static_cast<double>(f.origBytes);
        c.dstBytes = static_cast<double>(f.respBytes);
        c.srcPackets = f.origPkts; c.dstPackets = f.respPkts;
        c.land = (f.origIp == f.respIp && f.origPort == f.respPort) ? 1 : 0;
        c.wrongFragment = std::min(3, f.badFrag);
        c.urgent = f.urgent;
        conns.push_back(c);
    }
    features::computeTrafficFeatures(conns);
    json preds = ModelRegistry::instance().predictNids(conns);
    bool mlAvailable = preds.size() == conns.size() && !conns.empty();

    // ---- alerts
    json alerts = json::array();
    auto addAlert = [&](const std::string& type, const std::string& severity, const std::string& category,
                        const std::string& src, const std::string& dst, const std::string& evidence, long count,
                        double first, double last, json m, const std::string& source = "rule") {
        alerts.push_back({{"type", type}, {"severity", severity}, {"category", category}, {"src", src}, {"dst", dst},
                          {"evidence", evidence}, {"count", count}, {"firstSeen", first}, {"lastSeen", last},
                          {"mitreAttack", m}, {"detectedBy", source}});
    };

    // Per (src,dst) and per (src,port) aggregates
    struct Agg { std::set<uint16_t> ports; std::set<std::string> hosts; long failed = 0, total = 0, s0 = 0; double first = 1e300, last = 0; };
    std::map<std::pair<std::string, std::string>, Agg> srcDst;
    std::map<std::pair<std::string, uint16_t>, Agg> srcPort;
    std::map<std::string, Agg> dstS0, icmpToDst, udpToDst;
    std::map<std::string, Agg> echoBySrc;
    std::map<std::tuple<std::string, std::string, uint16_t>, std::vector<double>> beacons;
    std::map<std::pair<std::string, std::string>, Agg> authAttempts;
    static const std::set<uint16_t> authPorts = {21, 22, 23, 3389, 445, 3306, 5432, 1433, 5900, 110, 143, 25};
    static const std::map<uint16_t, std::string> badPorts = {{4444, "Metasploit default"}, {5555, "Android ADB / RAT"}, {6667, "IRC (botnet C2)"},
                                                            {1337, "common backdoor"}, {31337, "Back Orifice"}, {12345, "NetBus"},
                                                            {6666, "IRC / backdoor"}, {9001, "Tor relay"}, {2323, "Mirai telnet"}};
    for (const auto& c : conns) {
        const Flow& f = flows[c.tag];
        bool failed = c.flag == "S0" || c.flag == "REJ" || c.flag == "RSTOS0" || c.flag == "SH";
        auto upd = [&](Agg& a) { a.total++; if (failed) a.failed++; if (c.flag == "S0") a.s0++; a.first = std::min(a.first, c.startTime); a.last = std::max(a.last, c.startTime); };
        if (c.protocol == "tcp" || c.protocol == "udp") {
            auto& sd = srcDst[{c.srcIp, c.dstIp}];
            sd.ports.insert(c.dstPort);
            upd(sd);
            auto& spg = srcPort[{c.srcIp, c.dstPort}];
            spg.hosts.insert(c.dstIp);
            upd(spg);
        }
        if (c.protocol == "tcp" && c.flag == "S0") { auto& d = dstS0[c.dstIp]; d.hosts.insert(c.srcIp); upd(d); }
        if (c.protocol == "icmp") {
            auto& d = icmpToDst[c.dstIp]; d.hosts.insert(c.srcIp); d.total += static_cast<long>(f.origPkts) - 1; upd(d);
            if (f.icmpType == 8) { auto& e = echoBySrc[c.srcIp]; e.hosts.insert(c.dstIp); upd(e); }
        }
        if (c.protocol == "udp") { auto& d = udpToDst[c.dstIp + ":" + std::to_string(c.dstPort)]; d.total += static_cast<long>(f.origPkts) - 1; upd(d); }
        if (c.protocol == "tcp" && !failed) beacons[{c.srcIp, c.dstIp, c.dstPort}].push_back(c.startTime);
        if (c.protocol == "tcp" && authPorts.count(c.dstPort)) upd(authAttempts[{c.srcIp, c.dstIp + ":" + std::to_string(c.dstPort)}]);
        if (badPorts.count(c.dstPort) && c.flag != "S0" && c.flag != "REJ")
            addAlert("suspicious_port", "Medium", "c2", c.srcIp, c.dstIp + ":" + std::to_string(c.dstPort),
                     "Established connection to port " + std::to_string(c.dstPort) + " (" + badPorts.at(c.dstPort) + ")", 1, c.startTime, c.startTime + c.duration,
                     mitre({{"T1571", "Non-Standard Port"}}));
        if (c.land) addAlert("land_attack", "High", "dos", c.srcIp, c.dstIp, "Packet with identical source and destination address/port (LAND attack)", 1, c.startTime, c.startTime,
                             mitre({{"T1499", "Endpoint Denial of Service"}}));
        if (c.wrongFragment) addAlert("malformed_fragments", "High", "dos", c.srcIp, c.dstIp,
                                      std::to_string(f.badFrag) + " malformed/overlapping IP fragment(s) (teardrop / ping-of-death style)", f.badFrag, c.startTime, c.startTime,
                                      mitre({{"T1499", "Endpoint Denial of Service"}}));
        if ((c.dstPort == 23 || c.dstPort == 21) && c.protocol == "tcp" && !failed)
            addAlert("cleartext_protocol", "Low", "policy", c.srcIp, c.dstIp + ":" + std::to_string(c.dstPort),
                     std::string(c.dstPort == 23 ? "Telnet" : "FTP") + " session: credentials travel unencrypted", 1, c.startTime, c.startTime,
                     mitre({{"T1040", "Network Sniffing"}}));
        if (c.srcBytes >= 50e6 && isPrivateIp(c.srcIp) && !isPrivateIp(c.dstIp))
            addAlert("large_outbound_transfer", "High", "exfiltration", c.srcIp, c.dstIp,
                     "Internal host uploaded " + std::to_string(static_cast<long>(c.srcBytes / 1e6)) + " MB to an external address in one connection", 1,
                     c.startTime, c.startTime + c.duration, mitre({{"T1048", "Exfiltration Over Alternative Protocol"}, {"T1041", "Exfiltration Over C2 Channel"}}));
    }
    for (auto& [k, a] : srcDst)
        if (a.ports.size() >= 20)
            addAlert("port_scan", a.ports.size() >= 100 ? "High" : "Medium", "probe", k.first, k.second,
                     std::to_string(a.ports.size()) + " distinct ports probed (" + std::to_string(a.failed) + " of " + std::to_string(a.total) + " attempts refused/unanswered)",
                     a.total, a.first, a.last, mitre({{"T1046", "Network Service Discovery"}, {"T1595.001", "Active Scanning: Scanning IP Blocks"}}));
    for (auto& [k, a] : srcPort)
        if (a.hosts.size() >= 20)
            addAlert("host_sweep", "Medium", "probe", k.first, "*:" + std::to_string(k.second),
                     "Port " + std::to_string(k.second) + " probed on " + std::to_string(a.hosts.size()) + " different hosts", a.total, a.first, a.last,
                     mitre({{"T1046", "Network Service Discovery"}, {"T1018", "Remote System Discovery"}}));
    for (auto& [dst, a] : dstS0)
        if (a.s0 >= 100 && (a.last - a.first) <= 30)
            addAlert("syn_flood", "Critical", "dos", a.hosts.size() > 1 ? std::to_string(a.hosts.size()) + " sources" : *a.hosts.begin(), dst,
                     std::to_string(a.s0) + " half-open TCP connections (SYN without handshake) within " + std::to_string(static_cast<int>(a.last - a.first + 1)) + " s",
                     a.s0, a.first, a.last, mitre({{"T1498.001", "Network Denial of Service: Direct Network Flood"}, {"T1499", "Endpoint Denial of Service"}}));
    for (auto& [dst, a] : icmpToDst)
        if (a.total >= 100 && (a.last - a.first) <= 30)
            addAlert("icmp_flood", "High", "dos", a.hosts.size() > 1 ? std::to_string(a.hosts.size()) + " sources" : *a.hosts.begin(), dst,
                     std::to_string(a.total) + " ICMP packets within " + std::to_string(static_cast<int>(a.last - a.first + 1)) + " s", a.total, a.first, a.last,
                     mitre({{"T1498", "Network Denial of Service"}}));
    for (auto& [src, a] : echoBySrc)
        if (a.hosts.size() >= 20)
            addAlert("ping_sweep", "Medium", "probe", src, std::to_string(a.hosts.size()) + " hosts", "ICMP echo requests sent to " + std::to_string(a.hosts.size()) + " different hosts",
                     a.total, a.first, a.last, mitre({{"T1018", "Remote System Discovery"}}));
    for (auto& [dst, a] : udpToDst)
        if (a.total >= 500 && (a.last - a.first) <= 30)
            addAlert("udp_flood", "High", "dos", "-", dst, std::to_string(a.total) + " UDP packets to one service within " + std::to_string(static_cast<int>(a.last - a.first + 1)) + " s",
                     a.total, a.first, a.last, mitre({{"T1498.001", "Network Denial of Service: Direct Network Flood"}}));
    for (auto& [k, a] : authAttempts)
        if (a.total >= 15 && (a.last - a.first) <= 120)
            addAlert("brute_force_suspected", a.total >= 50 ? "High" : "Medium", "r2l", k.first, k.second,
                     std::to_string(a.total) + " connections to an authentication service within " + std::to_string(static_cast<int>(a.last - a.first + 1)) + " s",
                     a.total, a.first, a.last, mitre({{"T1110", "Brute Force"}, {"T1110.003", "Password Spraying"}}));
    for (auto& [k, times] : beacons) {
        if (times.size() < 6) continue;
        std::sort(times.begin(), times.end());
        std::vector<double> gaps;
        for (size_t i = 1; i < times.size(); ++i) gaps.push_back(times[i] - times[i - 1]);
        double m = 0, v = 0;
        for (double g : gaps) m += g;
        m /= gaps.size();
        for (double g : gaps) v += (g - m) * (g - m);
        double cv = m > 0 ? std::sqrt(v / gaps.size()) / m : 1;
        if (m >= 5 && cv < 0.15 && !isPrivateIp(std::get<1>(k)))
            addAlert("beaconing", "High", "c2", std::get<0>(k), std::get<1>(k) + ":" + std::to_string(std::get<2>(k)),
                     std::to_string(times.size()) + " connections at a regular ~" + std::to_string(static_cast<int>(m)) + " s interval (jitter " +
                         std::to_string(static_cast<int>(cv * 100)) + "%), typical of malware command-and-control",
                     static_cast<long>(times.size()), times.front(), times.back(),
                     mitre({{"T1071", "Application Layer Protocol"}, {"T1029", "Scheduled Transfer"}}));
    }
    // DNS tunnelling / exfiltration via DNS
    {
        std::map<std::pair<std::string, std::string>, std::pair<std::set<std::string>, long>> byDomain;
        std::map<std::pair<std::string, std::string>, std::pair<double, double>> span;
        for (auto& q : dnsQs) {
            ParsedUrl u = parseUrl("http://" + q.name);
            std::string reg = u.registrableDomain.empty() ? q.name : u.registrableDomain;
            auto& e = byDomain[{q.src, reg}];
            e.first.insert(u.subdomain);
            size_t longest = 0, cur = 0;
            for (char ch : q.name) { if (ch == '.') { longest = std::max(longest, cur); cur = 0; } else cur++; }
            longest = std::max(longest, cur);
            if (longest >= 40 || (q.name.size() >= 90 && shannonEntropy(u.subdomain) > 4.0)) e.second++;
            auto& sp = span[{q.src, reg}];
            if (sp.first == 0) sp.first = q.ts;
            sp.second = q.ts;
        }
        for (auto& [k, v] : byDomain)
            if (v.second >= 3 || v.first.size() >= 50)
                addAlert("dns_tunneling", "High", "exfiltration", k.first, k.second,
                         std::to_string(v.first.size()) + " unique subdomains queried under " + k.second + ", " + std::to_string(v.second) +
                             " with very long/high-entropy labels (data encoded in DNS queries)",
                         static_cast<long>(v.first.size()), span[k].first, span[k].second,
                         mitre({{"T1071.004", "Application Layer Protocol: DNS"}, {"T1048", "Exfiltration Over Alternative Protocol"}}));
    }
    // ML-detected connections grouped by (src, dst, category)
    json flowRows = json::array();
    std::map<std::string, long> mlByCategory;
    long mlFlagged = 0, novelCount = 0;
    if (mlAvailable) {
        struct MlGroup { long count = 0; double maxP = 0, first = 1e300, last = 0; json feats; std::map<std::string, long> sources; bool novel = false; };
        // grouped by (destination, category) so a flood from many spoofed sources is ONE alert
        std::map<std::pair<std::string, std::string>, MlGroup> groups;
        for (size_t i = 0; i < conns.size(); ++i) {
            const auto& c = conns[i];
            const auto& pr = preds[i];
            double p = pr["attackProbability"].get<double>();
            if (pr["novel"].get<bool>()) novelCount++;
            if (p < 0.5) continue;
            mlFlagged++;
            std::string cat = pr["category"].get<std::string>();
            if (cat == "normal") cat = pr["novel"].get<bool>() ? "anomaly" : "suspicious";
            mlByCategory[cat]++;
            auto& g = groups[{c.dstIp, cat}];
            g.count++;
            g.sources[c.srcIp]++;
            g.first = std::min(g.first, c.startTime);
            g.last = std::max(g.last, c.startTime);
            g.novel = g.novel || pr["novel"].get<bool>();
            if (p > g.maxP) { g.maxP = p; if (pr.contains("topFeatures")) g.feats = pr["topFeatures"]; }
        }
        // A single source hitting many hosts (sweep / worm) = ONE alert, not one per host.
        std::map<std::pair<std::string, std::string>, std::vector<std::string>> bySrc;
        for (auto& [k, g] : groups)
            if (g.sources.size() == 1) bySrc[{g.sources.begin()->first, k.second}].push_back(k.first);
        for (auto& [sk, dsts] : bySrc) {
            if (dsts.size() < 5) continue;
            MlGroup merged;
            for (auto& d : dsts) {
                auto& g = groups[{d, sk.second}];
                merged.count += g.count;
                merged.first = std::min(merged.first, g.first);
                merged.last = std::max(merged.last, g.last);
                merged.novel = merged.novel || g.novel;
                if (g.maxP > merged.maxP) { merged.maxP = g.maxP; merged.feats = g.feats; }
                groups.erase({d, sk.second});
            }
            merged.sources[sk.first] = merged.count;
            std::string label = std::to_string(dsts.size()) + " hosts";
            groups[{label, sk.second}] = merged;
        }
        for (auto& [k, g] : groups) {
            std::string cat = k.second;
            std::string srcLabel = g.sources.size() == 1 ? g.sources.begin()->first : std::to_string(g.sources.size()) + " sources";
            std::string sev = g.maxP >= 0.9 ? "High" : "Medium";
            json m = cat == "dos" ? mitre({{"T1499", "Endpoint Denial of Service"}})
                     : cat == "probe" ? mitre({{"T1046", "Network Service Discovery"}})
                     : cat == "r2l" ? mitre({{"T1110", "Brute Force"}, {"T1133", "External Remote Services"}})
                     : cat == "u2r" ? mitre({{"T1068", "Exploitation for Privilege Escalation"}})
                                    : mitre({{"T1071", "Application Layer Protocol"}});
            std::string ev = std::to_string(g.count) + " connection(s) classified as " + cat + " by the ML ensemble (max probability " +
                             std::to_string(static_cast<int>(g.maxP * 100)) + "%)" + (g.novel ? "; traffic pattern also unlike any normal training traffic" : "");
            addAlert("ml_" + cat, sev, cat, srcLabel, k.first, ev, g.count, g.first, g.last, m, "ml");
            alerts.back()["topFeatures"] = g.feats;
            std::vector<std::pair<long, std::string>> srcs;
            for (auto& [ip, n] : g.sources) srcs.push_back({n, ip});
            std::sort(srcs.rbegin(), srcs.rend());
            json topSrc = json::array();
            for (size_t i = 0; i < srcs.size() && i < 5; ++i) topSrc.push_back({{"ip", srcs[i].second}, {"connections", srcs[i].first}});
            alerts.back()["topSources"] = topSrc;
            alerts.back()["mlProbability"] = g.maxP;
        }
    }
    // flows table (highest risk first)
    std::vector<size_t> order(conns.size());
    std::iota(order.begin(), order.end(), 0);
    if (mlAvailable)
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return preds[a]["attackProbability"].get<double>() > preds[b]["attackProbability"].get<double>(); });
    for (size_t k = 0; k < order.size() && flowRows.size() < opt.maxFlowsInReport; ++k) {
        const auto& c = conns[order[k]];
        json r = {{"src", c.srcIp}, {"sport", c.srcPort}, {"dst", c.dstIp}, {"dport", c.dstPort}, {"proto", c.protocol},
                  {"service", c.service}, {"flag", c.flag}, {"start", c.startTime}, {"duration", c.duration},
                  {"srcBytes", c.srcBytes}, {"dstBytes", c.dstBytes}, {"packets", c.srcPackets + c.dstPackets}};
        if (mlAvailable) {
            r["attackProbability"] = preds[order[k]]["attackProbability"];
            r["category"] = preds[order[k]]["category"];
            r["novel"] = preds[order[k]]["novel"];
        }
        const Flow& f = flows[c.tag];
        if (!f.dnsQueries.empty()) r["dnsQueries"] = f.dnsQueries;
        flowRows.push_back(r);
    }
    std::sort(alerts.begin(), alerts.end(), [](const json& a, const json& b) {
        int ra = sevRank(a["severity"]), rb = sevRank(b["severity"]);
        return ra != rb ? ra > rb : a["count"].get<long>() > b["count"].get<long>();
    });
    int maxSev = 0;
    std::map<std::string, long> byCategory;
    for (auto& a : alerts) { maxSev = std::max(maxSev, sevRank(a["severity"])); byCategory[a["category"]]++; }
    static const char* levels[] = {"Safe", "Low", "Medium", "High", "Critical"};
    int score = maxSev == 0 ? 0 : maxSev == 1 ? 20 : maxSev == 2 ? 45 : maxSev == 3 ? 75 : 95;
    std::vector<std::pair<uint64_t, std::string>> talkers;
    for (auto& [ip, bytes] : talkerBytes) talkers.push_back({bytes, ip});
    std::sort(talkers.rbegin(), talkers.rend());
    json top = json::array();
    for (size_t i = 0; i < talkers.size() && i < 8; ++i) top.push_back({{"ip", talkers[i].second}, {"bytes", talkers[i].first}, {"internal", isPrivateIp(talkers[i].second)}});

    return json{
        {"source", sourceLabel},
        {"summary", {{"packets", packets.size()}, {"decodedPackets", decoded}, {"bytes", totalBytes}, {"connections", conns.size()},
                     {"durationSeconds", decoded ? tMax - tMin : 0}, {"protocols", protoCount}, {"dnsQueries", dnsQs.size()},
                     {"mlFlaggedConnections", mlFlagged}, {"novelConnections", novelCount}, {"mlByCategory", mlByCategory},
                     {"alertsByCategory", byCategory}, {"topTalkers", top}}},
        {"mlAvailable", mlAvailable},
        {"score", score},
        {"riskLevel", levels[maxSev]},
        {"alerts", alerts},
        {"flows", flowRows}};
}

json analyzeCaptureBytes(const std::string& bytes, const std::string& sourceLabel) {
    std::vector<RawPacket> packets;
    std::string err;
    if (!readCaptureFile(bytes, packets, err)) return json{{"error", err}};
    return analyzePackets(packets, sourceLabel);
}

}  // namespace cyberguard::nids
