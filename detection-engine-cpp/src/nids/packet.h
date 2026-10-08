#pragma once
// Packet capture parsing and decoding for the CyberGuard NIDS.
#include <cstdint>
#include <string>
#include <vector>

namespace cyberguard::nids {

struct RawPacket {
    double ts = 0;
    uint32_t linkType = 1;
    uint32_t origLen = 0;
    std::string data;  // captured bytes
};

// Reads classic libpcap (.pcap, us/ns, both endians) and pcapng files.
bool readCaptureFile(const std::string& bytes, std::vector<RawPacket>& out, std::string& error);

struct DecodedPacket {
    double ts = 0;
    bool valid = false;
    int ipVersion = 0;
    std::string src, dst;
    std::string proto;  // tcp | udp | icmp | other
    uint16_t sport = 0, dport = 0;
    uint8_t tcpFlags = 0;  // FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
    int icmpType = -1, icmpCode = -1;
    uint16_t icmpId = 0;
    uint32_t payloadLen = 0;
    uint32_t wireLen = 0;
    bool fragment = false, badFragment = false;
    std::string dnsQuery;  // first question name for UDP/53 queries
};

DecodedPacket decodePacket(const RawPacket& p);

}  // namespace cyberguard::nids
