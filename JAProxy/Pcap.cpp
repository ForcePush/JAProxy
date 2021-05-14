#include "Pcap.h"
#include <memory>

#include <pcap/pcap.h>

// Source: https://github.com/p0f/p0f/blob/master/process.c
constexpr int UNKNOWN_DATALINK = std::numeric_limits<int>::min();
constexpr int getIPOffset(int datalink) noexcept
{
    switch (datalink) {
    case DLT_RAW: return 0;

    case DLT_NULL:
    case DLT_PPP: return 4;

    case DLT_LOOP:

#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL:
#endif // DLT_PPP_SERIAL

    case DLT_PPP_ETHER:  return 8;

    case DLT_EN10MB: return 14;

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL: return 16;
#endif  // DLT_LINUX_SLL
    case DLT_PFLOG: return 28;
    case DLT_IEEE802_11: return 32;
    }

    return UNKNOWN_DATALINK;
}

std::optional<boost::asio::ip::address> fromSockaddr(const sockaddr *addr)
{
    if (!addr) {
        return {};
    }

    if (addr->sa_family == AF_INET) {
        auto addr4 = reinterpret_cast<const sockaddr_in *>(addr);
        return boost::asio::ip::make_address_v4(ntohl(addr4->sin_addr.s_addr));
    } else if (addr->sa_family == AF_INET6) {
        auto addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
        boost::asio::ip::address_v6::bytes_type buf;
        memcpy(buf.data(), addr6->sin6_addr.s6_addr, sizeof(addr6->sin6_addr));
        return boost::asio::ip::make_address_v6(buf, addr6->sin6_scope_id);
    }

    return {};
}

PcapResult Pcap::initialize()
{
#ifdef PCAP_AVAILABLE_1_10
    return Pcap::initialize(PCAP_CHAR_ENC_LOCAL);
#else
    return Pcap::initialize(0);
#endif
}

PcapResult Pcap::initialize(unsigned int pcap_char_enc)
{
    if (initialized) {
        return PcapResult::success(0);
    }
#ifdef PCAP_AVAILABLE_1_10
    char errbuf[PCAP_ERRBUF_SIZE]{};
    int res = pcap_init(pcap_char_enc, errbuf);
    initialized = (res == 0);
    return PcapResult::successOnZero(res, errbuf);
#else  // PCAP_AVAILABLE_1_10
    static_cast<void>(pcap_char_enc);
#ifdef _MSC_VER
    int res = pcap_wsockinit();
    initialized = (res == 0);
    return PcapResult::successOnZero(res, "Failed to initialize winsock");
#else  // _MSC_VER
    return PcapResult::success(0);
#endif  // _MSC_VER
#endif  // PCAP_AVAILABLE_1_10
}

struct AllDevsDeleter {
    void operator()(void *devs)
    {
        if (devs) {
            pcap_freealldevs(reinterpret_cast<pcap_if_t *>(devs));
        }
    }
};

PcapAddress pcapAddrFromRaw(const pcap_addr_t *rawAddr)
{
    PcapAddress res;

    if (rawAddr->addr) {
        res.addr = fromSockaddr(rawAddr->addr).value_or(boost::asio::ip::address{});
    }

    if (rawAddr->netmask) {
        res.netmask = fromSockaddr(rawAddr->netmask);
    }

    if (rawAddr->broadaddr) {
        res.broadaddr = fromSockaddr(rawAddr->broadaddr);
    }

    if (rawAddr->dstaddr) {
        res.dstaddr = fromSockaddr(rawAddr->dstaddr);
    }

    return res;
}


InterfacesResult Pcap::listInterfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    std::vector<PcapInterface> res;
    pcap_if_t *iface = nullptr;

    int pcap_res = pcap_findalldevs(&iface, errbuf);
    std::unique_ptr<pcap_if_t, AllDevsDeleter> ifaceGuard{ iface };

    if (pcap_res != 0) {
        return InterfacesResult::fail(errbuf);
    }

    if (!iface) {
        return InterfacesResult::fail(std::move(res), "No interfaces found");
    }

    do {
        PcapInterface curIface{};
        curIface.name = iface->name;
        if (iface->description) {
            curIface.description = iface->description;
        }
        curIface.flags = iface->flags;

        pcap_addr_t *curAddr = iface->addresses;
        while (curAddr) {
            curIface.addresses.emplace_back(pcapAddrFromRaw(curAddr));
            curAddr = curAddr->next;
        }

        res.emplace_back(std::move(curIface));

        iface = iface->next;
    } while (iface);

    return InterfacesResult::success(std::move(res));
}

Result<Pcap> Pcap::create(const PcapInterface & iface)
{
    return Pcap::create(iface.name.data());
}

Result<Pcap> Pcap::create(const char *ifaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t *handle = pcap_create(ifaceName, errbuf);
    if (!handle) {
        return Result<Pcap>::fail(errbuf);
    } else {
        return Result<Pcap>::success(Pcap(handle));
    }
}

static pcap_t *castPcap(void *pcapHandleVoid)
{
    return reinterpret_cast<pcap_t *>(pcapHandleVoid);
}

Pcap::Pcap(void *pcapHandle_) : 
    pcapHandle(pcapHandle_)
{
}

PcapResult Pcap::successOnZeroGeterror(int result)
{
    return PcapResult::successOnZeroLazy(result, [this](int) { return pcap_geterr(castPcap(pcapHandle)); });
}

char *Pcap::pcap_geterr_wrapper() const
{
    return pcap_geterr(castPcap(pcapHandle));
}

Result<int> Pcap::setTimeoutMs(int ms)
{
    return Result<int>::successOnZeroLazy(pcap_set_timeout(castPcap(pcapHandle), ms),
                                          [this](int) { return pcap_geterr_wrapper(); });
}

bool Pcap::isDatalinkKnown(int datalink) noexcept
{
    return getIPOffset(datalink) != UNKNOWN_DATALINK;
}


extern "C" void worker_wrapper(unsigned char *callbackPtr,
                               const pcap_pkthdr * header,
                               const unsigned char *bytes)
{
    assert(callbackPtr != nullptr);
    assert(header != nullptr);

    const PcapCallback & callback = *reinterpret_cast<const PcapCallback *>(callbackPtr);
    callback(PcapPacket{ header->ts, header->len, { bytes, header->caplen } });
}

struct WorkerWrapperIPParams {
    const PcapCallback & callback;
    int datalinkOffset;
};

extern "C" void worker_wrapper_ip(unsigned char *paramsPtr,
                                  const pcap_pkthdr * header,
                                  const unsigned char *bytes)
{
    assert(paramsPtr != nullptr);
    assert(header != nullptr);

    const auto & params = *reinterpret_cast<const WorkerWrapperIPParams *>(paramsPtr);

    auto offset = static_cast<decltype(header->len)>(params.datalinkOffset);

    if (header->len < offset) {
        return;  // Invalid packet
    }

    auto advancedLen = header->len - offset;
    auto caplenOffset = std::min(header->caplen, offset);
    auto advancedCaplen = header->caplen - caplenOffset;
    bytes += caplenOffset;

    params.callback(PcapPacket{ header->ts, advancedLen, { bytes, advancedCaplen } });
}

bool Pcap::startLoopBlocking(PcapCallback callback, int count)
{
    pcap_loop(castPcap(pcapHandle), count, &worker_wrapper,
              reinterpret_cast<unsigned char *>(std::addressof(callback)));
    return true;
}

PcapResult Pcap::startLoopIPBlocking(PcapCallback callback, int count)
{
    int link = getDatalink();
    auto IPOffset = getIPOffset(link);
    if (IPOffset == UNKNOWN_DATALINK) {
        return PcapResult::fail("Unknown datalink");
    }

    auto params = WorkerWrapperIPParams{ std::move(callback), IPOffset };

    pcap_loop(castPcap(pcapHandle), count, &worker_wrapper_ip,
              reinterpret_cast<unsigned char *>(std::addressof(params)));

    return PcapResult::success(0);
}

std::future<bool> Pcap::startLoop(PcapCallback callback, int count)
{
    return std::async(std::launch::async, [this, count, cb = std::move(callback)]() mutable {
        return startLoopBlocking(std::move(cb), count);
    });
}

std::future<PcapResult> Pcap::startLoopIP(PcapCallback callback, int count)
{
    return std::async(std::launch::async, [this, count, cb = std::move(callback)]() mutable {
        return startLoopIPBlocking(std::move(cb), count);
    });
}

void Pcap::breakLoop()
{
    pcap_breakloop(castPcap(pcapHandle));
}

Pcap::~Pcap()
{
    if (pcapHandle) {
        pcap_close(castPcap(pcapHandle));
    }
}

int Pcap::getDatalink() noexcept
{
    return pcap_datalink(castPcap(pcapHandle));
}

Result<std::set<int>> Pcap::getSupportedDatalinks()
{
    using ResType = Result<std::set<int>>;
    struct DatalinkListDeleter {
        void operator()(int *ptr) noexcept
        {
            if (ptr) {
                pcap_free_datalinks(ptr);
            }
        }
    };

    int *links = nullptr;
    int res = pcap_list_datalinks(castPcap(pcapHandle), &links);
    std::unique_ptr<int, DatalinkListDeleter> guard{ links };

    if (res == PCAP_ERROR_NOT_ACTIVATED) {
        return ResType::fail("Pcap handle is not activated");
    } else if (res == PCAP_ERROR) {
        return ResType::fail(pcap_geterr(castPcap(pcapHandle)));
    } else if (res <= 0) {
        return ResType::fail("Pcap returned invalid supported datalinks count");
    } else {
        return ResType::success(std::set<int>(links, links + res));
    }
}

PcapResult Pcap::setDatalink(int newDatalink)
{
    return successOnZeroGeterror(pcap_set_datalink(castPcap(pcapHandle), newDatalink));
}

PcapResult Pcap::setImmediateMode(bool enabled)
{
    return successOnZeroGeterror(pcap_set_immediate_mode(castPcap(pcapHandle), static_cast<int>(enabled)));
}

PcapResult Pcap::setSnaplen(int snaplen)
{
    return successOnZeroGeterror(pcap_set_snaplen(castPcap(pcapHandle), snaplen));
}

struct BpfProgramDeleter {
    void operator()(void *ptr) const noexcept
    {
        pcap_freecode(reinterpret_cast<bpf_program*>(ptr));
    }
};

PcapResult Pcap::setFilter(const std::string & filterStr, bool optimize)
{
    return setFilter(filterStr, PCAP_NETMASK_UNKNOWN, optimize);
}

PcapResult Pcap::setFilter(const std::string & filterStr, uint32_t netmask, bool optimize)
{
    return setFilter(filterStr.data(), optimize, netmask);
}

PcapResult Pcap::setFilter(const char *filterStr, bool optimize)
{
    return setFilter(filterStr, PCAP_NETMASK_UNKNOWN, optimize);
}

PcapResult Pcap::setFilter(const char *filterStr, uint32_t netmask, bool optimize)
{
    bpf_program prog;
    int compileRes = pcap_compile(castPcap(pcapHandle), &prog, filterStr, static_cast<int>(optimize), netmask);
    if (compileRes != 0) {
        return PcapResult::fail(compileRes, pcap_geterr(castPcap(pcapHandle)));
    }
    std::unique_ptr<bpf_program, BpfProgramDeleter> progGuard{ &prog };

    return successOnZeroGeterror(pcap_setfilter(castPcap(pcapHandle), &prog));
}

PcapResult Pcap::activate()
{
    return successOnZeroGeterror(pcap_activate(castPcap(pcapHandle)));
}
