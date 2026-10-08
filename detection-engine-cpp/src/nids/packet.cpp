#include "packet.h"

#include <cmath>
#include <cstring>

namespace cyberguard::nids {

namespace {
uint16_t be16(const unsigned char* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t rd32(const std::string& b, size_t o, bool swap) {
    uint32_t v;
    std::memcpy(&v, b.data() + o, 4);
    if (swap) v = __builtin_bswap32(v);
    return v;
}
uint16_t rd16(const std::string& b, size_t o, bool swap) {
    uint16_t v;
    std::memcpy(&v, b.data() + o, 2);
    if (swap) v = __builtin_bswap16(v);
    return v;
}
std::string ipv4(const unsigned char* p) {
    return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." + std::to_string(p[2]) + "." + std::to_string(p[3]);
}
std::string ipv6(const unsigned char* p) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; i += 2) {
        if (i) s += ':';
        uint16_t v = be16(p + i);
        bool started = false;
        for (int sh = 12; sh >= 0; sh -= 4) {
            int d = (v >> sh) & 15;
            if (d || started || sh == 0) { s += hex[d]; started = true; }
        }
    }
    return s;
}
}  // namespace

bool readCaptureFile(const std::string& b, std::vector<RawPacket>& out, std::string& error) {
    out.clear();
    if (b.size() < 24) { error = "file too small to be a capture"; return false; }
    uint32_t magic;
    std::memcpy(&magic, b.data(), 4);
    // ---- classic pcap
    if (magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1 || magic == 0xa1b23c4d || magic == 0x4d3cb2a1) {
        bool swap = (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1);
        bool nano = (magic == 0xa1b23c4d || magic == 0x4d3cb2a1);
        uint32_t link = rd32(b, 20, swap);
        size_t pos = 24;
        while (pos + 16 <= b.size()) {
            uint32_t sec = rd32(b, pos, swap), frac = rd32(b, pos + 4, swap), incl = rd32(b, pos + 8, swap), orig = rd32(b, pos + 12, swap);
            pos += 16;
            if (incl > 262144 || pos + incl > b.size()) break;
            RawPacket p;
            p.ts = sec + frac / (nano ? 1e9 : 1e6);
            p.linkType = link;
            p.origLen = orig;
            p.data = b.substr(pos, incl);
            out.push_back(std::move(p));
            pos += incl;
        }
        return true;
    }
    // ---- pcapng
    if (magic == 0x0a0d0d0a) {
        size_t pos = 0;
        bool swap = false;
        std::vector<uint32_t> ifLink;
        std::vector<double> ifRes;
        while (pos + 12 <= b.size()) {
            uint32_t type = rd32(b, pos, swap);
            if (type == 0x0a0d0d0a) {
                uint32_t bom;
                std::memcpy(&bom, b.data() + pos + 8, 4);
                swap = (bom == 0x4d3c2b1a);
                ifLink.clear();
                ifRes.clear();
            }
            uint32_t len = rd32(b, pos + 4, swap);
            if (len < 12 || pos + len > b.size()) break;
            if (type == 1 && len >= 20) {  // Interface Description Block
                ifLink.push_back(rd16(b, pos + 8, swap));
                double res = 1e-6;
                size_t opt = pos + 16;
                while (opt + 4 <= pos + len - 4) {
                    uint16_t code = rd16(b, opt, swap), olen = rd16(b, opt + 2, swap);
                    if (code == 0) break;
                    if (code == 9 && olen >= 1) {
                        uint8_t v = static_cast<uint8_t>(b[opt + 4]);
                        res = (v & 0x80) ? std::pow(2.0, -(v & 0x7f)) : std::pow(10.0, -static_cast<int>(v));
                    }
                    opt += 4 + ((olen + 3) & ~3u);
                }
                ifRes.push_back(res);
            } else if (type == 6 && len >= 32) {  // Enhanced Packet Block
                uint32_t ifid = rd32(b, pos + 8, swap);
                uint64_t ts = (static_cast<uint64_t>(rd32(b, pos + 12, swap)) << 32) | rd32(b, pos + 16, swap);
                uint32_t cap = rd32(b, pos + 20, swap), orig = rd32(b, pos + 24, swap);
                if (pos + 28 + cap <= b.size() && cap <= 262144) {
                    RawPacket p;
                    p.ts = ts * (ifid < ifRes.size() ? ifRes[ifid] : 1e-6);
                    p.linkType = ifid < ifLink.size() ? ifLink[ifid] : 1;
                    p.origLen = orig;
                    p.data = b.substr(pos + 28, cap);
                    out.push_back(std::move(p));
                }
            } else if (type == 3 && len >= 16) {  // Simple Packet Block
                uint32_t orig = rd32(b, pos + 8, swap);
                uint32_t cap = std::min<uint32_t>(orig, len - 16);
                RawPacket p;
                p.ts = out.empty() ? 0 : out.back().ts;
                p.linkType = ifLink.empty() ? 1 : ifLink[0];
                p.origLen = orig;
                p.data = b.substr(pos + 12, cap);
                out.push_back(std::move(p));
            }
            pos += len;
        }
        return true;
    }
    error = "unrecognised capture format (expected .pcap or .pcapng)";
    return false;
}

static std::string parseDnsName(const unsigned char* d, size_t len, size_t off) {
    std::string name;
    int guard = 0;
    while (off < len && guard++ < 64) {
        uint8_t l = d[off];
        if (l == 0) break;
        if ((l & 0xC0) == 0xC0) break;  // compression pointer (not in first question normally)
        if (off + 1 + l > len) break;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(d + off + 1), l);
        off += 1 + l;
    }
    return name;
}

DecodedPacket decodePacket(const RawPacket& p) {
    DecodedPacket d;
    d.ts = p.ts;
    d.wireLen = p.origLen;
    const auto* data = reinterpret_cast<const unsigned char*>(p.data.data());
    size_t len = p.data.size(), off = 0;
    uint16_t etherType = 0;
    switch (p.linkType) {
        case 1:  // Ethernet
            if (len < 14) return d;
            etherType = be16(data + 12);
            off = 14;
            while ((etherType == 0x8100 || etherType == 0x88a8) && off + 4 <= len) { etherType = be16(data + off + 2); off += 4; }
            break;
        case 113:  // Linux cooked (SLL)
            if (len < 16) return d;
            etherType = be16(data + 14);
            off = 16;
            break;
        case 276:  // SLL2
            if (len < 20) return d;
            etherType = be16(data);
            off = 20;
            break;
        case 0: case 108:  // BSD loopback / null
            if (len < 4) return d;
            off = 4;
            etherType = ((data[4] >> 4) == 6) ? 0x86dd : 0x0800;
            break;
        case 101: case 12: case 14: case 228: case 229:  // raw IP
            etherType = (len && (data[0] >> 4) == 6) ? 0x86dd : 0x0800;
            break;
        default:
            return d;
    }
    uint8_t l4 = 0;
    size_t l4off = 0, l4len = 0;
    // l4len = bytes actually captured (bounds for header parsing);
    // wl4   = layer-4 length on the wire from the IP header, so captures saved
    //         truncated (tcpdump -s 96) still report true traffic volume.
    size_t wl4 = 0;
    if (etherType == 0x0800) {
        if (off + 20 > len) return d;
        const unsigned char* ip = data + off;
        size_t ihl = (ip[0] & 15) * 4;
        uint16_t total = be16(ip + 2);
        uint16_t fragField = be16(ip + 6);
        uint16_t fragOff = fragField & 0x1FFF;
        bool mf = fragField & 0x2000;
        d.ipVersion = 4;
        d.src = ipv4(ip + 12);
        d.dst = ipv4(ip + 16);
        l4 = ip[9];
        d.fragment = mf || fragOff;
        if (d.fragment) {
            size_t fragLen = total > ihl ? total - ihl : 0;
            if (static_cast<size_t>(fragOff) * 8 + fragLen > 65535 || (mf && fragLen % 8 != 0) || (mf && fragLen < 8)) d.badFragment = true;
        }
        l4off = off + ihl;
        size_t end = std::min(len, off + std::max<size_t>(total, ihl));
        l4len = end > l4off ? end - l4off : 0;
        wl4 = total > ihl ? total - ihl : l4len;   // total == 0 (TSO offload) -> fall back to captured
        if (fragOff) { d.proto = l4 == 6 ? "tcp" : l4 == 17 ? "udp" : l4 == 1 ? "icmp" : "other"; d.valid = true; d.payloadLen = static_cast<uint32_t>(wl4); return d; }
    } else if (etherType == 0x86dd) {
        if (off + 40 > len) return d;
        const unsigned char* ip = data + off;
        d.ipVersion = 6;
        d.src = ipv6(ip + 8);
        d.dst = ipv6(ip + 24);
        l4 = ip[6];
        l4off = off + 40;
        size_t guard = 0;
        while ((l4 == 0 || l4 == 43 || l4 == 60 || l4 == 44) && l4off + 8 <= len && guard++ < 6) {
            if (l4 == 44) d.fragment = true;
            uint8_t next = data[l4off];
            l4off += (l4 == 44) ? 8 : (data[l4off + 1] + 1) * 8;
            l4 = next;
        }
        l4len = len > l4off ? len - l4off : 0;
        {
            size_t plen = be16(ip + 4), hdrs = l4off - (off + 40);
            wl4 = plen > hdrs ? plen - hdrs : l4len;
        }
        if (l4 == 58) l4 = 1;  // ICMPv6 treated as icmp
    } else {
        return d;
    }
    const unsigned char* t = data + l4off;
    if (l4 == 6 && l4len >= 20) {
        d.proto = "tcp";
        d.sport = be16(t);
        d.dport = be16(t + 2);
        size_t doff = (t[12] >> 4) * 4;
        d.tcpFlags = t[13];
        d.payloadLen = static_cast<uint32_t>(wl4 > doff ? wl4 - doff : 0);
    } else if (l4 == 17 && l4len >= 8) {
        d.proto = "udp";
        d.sport = be16(t);
        d.dport = be16(t + 2);
        d.payloadLen = static_cast<uint32_t>(wl4 > 8 ? wl4 - 8 : 0);
        if (d.dport == 53 && l4len > 8 + 12) {
            const unsigned char* dns = t + 8;
            size_t dl = l4len - 8;
            if (be16(dns + 4) >= 1 && !(dns[2] & 0x80)) d.dnsQuery = parseDnsName(dns, dl, 12);
        }
    } else if (l4 == 1 && l4len >= 4) {
        d.proto = "icmp";
        d.icmpType = t[0];
        d.icmpCode = t[1];
        if (l4len >= 8) d.icmpId = be16(t + 4);
        if (d.ipVersion == 6) {  // map ICMPv6 echo to v4 numbers
            if (d.icmpType == 128) d.icmpType = 8;
            else if (d.icmpType == 129) d.icmpType = 0;
            else if (d.icmpType == 1) d.icmpType = 3;
        }
        d.payloadLen = static_cast<uint32_t>(wl4 > 8 ? wl4 - 8 : 0);
    } else {
        d.proto = "other";
        d.payloadLen = static_cast<uint32_t>(wl4);
    }
    d.valid = true;
    return d;
}

}  // namespace cyberguard::nids
