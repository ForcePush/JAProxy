#pragma once
#include <atomic>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <numeric>
#include <chrono>
#include <future>

#include <boost/asio.hpp>

#include "Result.h"

struct PcapAddress {
    boost::asio::ip::address addr{};                        /* address */
    std::optional<boost::asio::ip::address> netmask{};      /* netmask for that address */
    std::optional<boost::asio::ip::address> broadaddr{};    /* broadcast address for that address */
    std::optional<boost::asio::ip::address> dstaddr{};      /* P2P destination address for that address */
};

struct PcapInterface {
    std::string name{};
    std::optional<std::string> description{};
    uint32_t flags{};
    std::vector<PcapAddress> addresses{};
};

struct PcapPacket {
    timeval ts;            /* time stamp */
    uint32_t full_len;     /* length of this packet (off wire) */
    std::basic_string_view<unsigned char> data;
};

using PcapResult = Result<int>;
using InterfacesResult = Result<std::vector<PcapInterface>>;
using PcapCallback = std::function<void(const PcapPacket & packet)>;

class Pcap {
public:
    static PcapResult initialize();
    static PcapResult initialize(unsigned int pcap_char_enc);
    static InterfacesResult listInterfaces();

    Pcap() noexcept = default;
    Pcap(const Pcap & other) = delete;
    Pcap(Pcap && other) noexcept : Pcap()
    {
        swap(*this, other);
    }

    Pcap & operator=(Pcap && other) noexcept
    {
        Pcap tmp{};
        swap(*this, tmp);
        swap(*this, other);
        return *this;
    }

    friend void swap(Pcap & a, Pcap & b) noexcept
    {
        using std::swap;
        swap(a.activated, b.activated);
        swap(a.pcapHandle, b.pcapHandle);
    }

    static Result<Pcap> create(const PcapInterface & iface);
    static Result<Pcap> create(const char *ifaceName);

    ~Pcap();

    int getDatalink() noexcept;
    Result<std::set<int>> getSupportedDatalinks();
    PcapResult setDatalink(int newDatalink);

    template<typename Rep, typename Period>
    PcapResult setTimeout(const std::chrono::duration<Rep, Period> & timeout)
    {
        auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
        if (timeout_ms > static_cast<decltype(timeout_ms)>(std::numeric_limits<int>::max())) {
            return PcapResult::fail("Too big timeout");
        }
        return setTimeoutMs(static_cast<int>(timeout_ms.count()));
    }
    PcapResult setImmediateMode(bool enabled);
    PcapResult setSnaplen(int snaplen);

    PcapResult activate();

    PcapResult setFilter(const std::string & filterStr, bool optimize = true);
    PcapResult setFilter(const std::string & filterStr, uint32_t netmask, bool optimize);
    PcapResult setFilter(const char *filterStr, bool optimize = true);
    PcapResult setFilter(const char *filterStr, uint32_t netmask, bool optimize);

    bool isDatalinkKnown(int datalink) noexcept;

    bool startLoopBlocking(PcapCallback callback, int count = -1);
    PcapResult startLoopIPBlocking(PcapCallback callback, int count = -1);
    std::future<bool> startLoop(PcapCallback callback, int count = -1);
    std::future<PcapResult> startLoopIP(PcapCallback callback, int count = -1);

    void breakLoop();

private:
    static inline bool initialized = false;

    void *pcapHandle = nullptr;
    bool activated = false;

    Pcap(void *pcapHandle_);

    PcapResult successOnZeroGeterror(int result);
    char *pcap_geterr_wrapper() const;
    Result<int> setTimeoutMs(int ms);
};
