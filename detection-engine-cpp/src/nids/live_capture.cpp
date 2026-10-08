#include "live_capture.h"

#include <atomic>
#include <chrono>
#include <ctime>
#include <deque>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

#include "nids_engine.h"
#include "packet.h"

#ifdef CG_WITH_PCAP
#include <pcap/pcap.h>
#include "httplib.h"
#endif

namespace cyberguard::nids {

LiveCapture& LiveCapture::instance() {
    static LiveCapture lc;
    return lc;
}

#ifndef CG_WITH_PCAP

bool LiveCapture::supported() { return false; }
json LiveCapture::interfaces() const { return json{{"supported", false}, {"interfaces", json::array()}}; }
json LiveCapture::start(const LiveOptions&) {
    return json{{"started", false}, {"error", "This engine build has no libpcap support. Rebuild with -DWITH_PCAP=ON (the Docker image does), or upload a .pcap file instead."}};
}
json LiveCapture::stop() { return json{{"stopped", false}}; }
json LiveCapture::status() const { return json{{"supported", false}, {"running", false}}; }

#else

struct LiveCapture::Impl {
    LiveOptions opt;
    pcap_t* handle = nullptr;
    int linkType = 1;
    std::atomic<bool> running{false};
    std::thread capThread, anaThread;
    mutable std::mutex mu;
    std::deque<RawPacket> buffer;
    uint64_t totalPackets = 0, totalBytes = 0;
    json lastAnalysis = nullptr;
    json alertHistory = json::array();
    std::set<std::string> seenAlertKeys;
    std::string lastError;
    double startedAt = 0;
};

bool LiveCapture::supported() { return true; }

json LiveCapture::interfaces() const {
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* devs = nullptr;
    json list = json::array();
    if (pcap_findalldevs(&devs, err) == 0) {
        for (pcap_if_t* d = devs; d; d = d->next)
            list.push_back({{"name", d->name}, {"description", d->description ? d->description : ""},
                            {"loopback", (d->flags & PCAP_IF_LOOPBACK) != 0}});
        pcap_freealldevs(devs);
    }
    return json{{"supported", true}, {"interfaces", list}, {"error", list.empty() ? std::string(err) : ""}};
}

static double nowSec() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

json LiveCapture::start(const LiveOptions& opt) {
    if (impl_ && impl_->running) return json{{"started", false}, {"error", "capture already running on " + impl_->opt.iface}};
    if (impl_) { delete impl_; impl_ = nullptr; }
    impl_ = new Impl();
    impl_->opt = opt;
    char err[PCAP_ERRBUF_SIZE];
    std::string iface = opt.iface;
    if (iface.empty()) {
        pcap_if_t* devs = nullptr;
        if (pcap_findalldevs(&devs, err) == 0 && devs) {
            for (pcap_if_t* d = devs; d; d = d->next)
                if (!(d->flags & PCAP_IF_LOOPBACK)) { iface = d->name; break; }
            pcap_freealldevs(devs);
        }
    }
    impl_->opt.iface = iface;
    impl_->handle = pcap_open_live(iface.c_str(), 262144, 1, 500, err);
    if (!impl_->handle) {
        impl_->lastError = err;
        return json{{"started", false}, {"error", std::string("pcap_open_live failed: ") + err +
                                                     " (needs root or CAP_NET_RAW/CAP_NET_ADMIN, and a valid interface name)"}};
    }
    if (!opt.bpf.empty()) {
        bpf_program prog;
        if (pcap_compile(impl_->handle, &prog, opt.bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(impl_->handle, &prog);
            pcap_freecode(&prog);
        }
    }
    impl_->linkType = pcap_datalink(impl_->handle);
    impl_->running = true;
    impl_->startedAt = nowSec();
    Impl* im = impl_;
    im->capThread = std::thread([im]() {
        pcap_pkthdr* hdr;
        const u_char* data;
        while (im->running) {
            int r = pcap_next_ex(im->handle, &hdr, &data);
            if (r == 1) {
                RawPacket p;
                p.ts = hdr->ts.tv_sec + hdr->ts.tv_usec / 1e6;
                p.linkType = static_cast<uint32_t>(im->linkType);
                p.origLen = hdr->len;
                p.data.assign(reinterpret_cast<const char*>(data), hdr->caplen);
                std::lock_guard<std::mutex> lock(im->mu);
                im->totalPackets++;
                im->totalBytes += hdr->len;
                im->buffer.push_back(std::move(p));
                while (im->buffer.size() > 400000) im->buffer.pop_front();
            } else if (r < 0) {
                std::lock_guard<std::mutex> lock(im->mu);
                im->lastError = pcap_geterr(im->handle);
                im->running = false;
            }
        }
    });
    im->anaThread = std::thread([im]() {
        while (im->running) {
            for (int i = 0; i < im->opt.analysisInterval * 10 && im->running; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!im->running) break;
            std::vector<RawPacket> window;
            double cutoff = nowSec() - im->opt.windowSeconds;
            {
                std::lock_guard<std::mutex> lock(im->mu);
                while (!im->buffer.empty() && im->buffer.front().ts < cutoff) im->buffer.pop_front();
                window.assign(im->buffer.begin(), im->buffer.end());
            }
            json a = analyzePackets(window, "live:" + im->opt.iface);
            json fresh = json::array();
            {
                std::lock_guard<std::mutex> lock(im->mu);
                for (auto& al : a["alerts"]) {
                    std::string key = al["type"].get<std::string>() + "|" + al["src"].get<std::string>() + "|" + al["dst"].get<std::string>();
                    if (im->seenAlertKeys.insert(key).second) {
                        json copy = al;
                        copy["detectedAt"] = nowSec();
                        im->alertHistory.push_back(copy);
                        fresh.push_back(copy);
                    }
                }
                while (im->alertHistory.size() > 500) im->alertHistory.erase(im->alertHistory.begin());
                a.erase("flows");
                im->lastAnalysis = a;
            }
            if (!im->opt.reportUrl.empty() && !fresh.empty()) {
                // http://host:port/path
                std::string url = im->opt.reportUrl;
                auto schemeEnd = url.find("://");
                std::string rest = schemeEnd == std::string::npos ? url : url.substr(schemeEnd + 3);
                auto slash = rest.find('/');
                std::string hostPort = rest.substr(0, slash), path = slash == std::string::npos ? "/" : rest.substr(slash);
                httplib::Client cli("http://" + hostPort);
                cli.set_connection_timeout(3);
                httplib::Headers h = {{"x-engine-key", im->opt.reportKey}};
                json body = {{"sensor", im->opt.sensorName}, {"iface", im->opt.iface}, {"alerts", fresh}, {"summary", a["summary"]},
                             {"riskLevel", a["riskLevel"]}, {"score", a["score"]}};
                auto res = cli.Post(path, h, body.dump(), "application/json");
                if (!res || res->status >= 300)
                    std::cerr << "[sensor] could not report " << fresh.size() << " alert(s) to " << im->opt.reportUrl << "\n";
                else
                    std::cout << "[sensor] reported " << fresh.size() << " new alert(s)\n";
            }
        }
    });
    return json{{"started", true}, {"iface", iface}, {"linkType", impl_->linkType}, {"bpf", opt.bpf}};
}

json LiveCapture::stop() {
    if (!impl_ || !impl_->running) return json{{"stopped", false}, {"error", "not running"}};
    impl_->running = false;
    if (impl_->handle) pcap_breakloop(impl_->handle);
    if (impl_->capThread.joinable()) impl_->capThread.join();
    if (impl_->anaThread.joinable()) impl_->anaThread.join();
    pcap_close(impl_->handle);
    impl_->handle = nullptr;
    return json{{"stopped", true}};
}

json LiveCapture::status() const {
    if (!impl_) return json{{"supported", true}, {"running", false}};
    std::lock_guard<std::mutex> lock(impl_->mu);
    return json{{"supported", true}, {"running", impl_->running.load()}, {"iface", impl_->opt.iface}, {"bpf", impl_->opt.bpf},
                {"startedAt", impl_->startedAt}, {"windowSeconds", impl_->opt.windowSeconds},
                {"packetsCaptured", impl_->totalPackets}, {"bytesCaptured", impl_->totalBytes},
                {"bufferedPackets", impl_->buffer.size()}, {"lastAnalysis", impl_->lastAnalysis},
                {"alerts", impl_->alertHistory}, {"lastError", impl_->lastError}};
}

#endif

}  // namespace cyberguard::nids
