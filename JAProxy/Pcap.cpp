#include "Pcap.h"
#include <memory>
#include <pcap/pcap.h>

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
    return Pcap::initialize(PCAP_CHAR_ENC_LOCAL);
}

PcapResult Pcap::initialize(unsigned int pcap_char_enc)
{
    if (initialized) {
        return PcapResult::success(0);
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    int res = pcap_init(pcap_char_enc, errbuf);
    initialized = (res == 0);
    return PcapResult::successOnZero(res, errbuf);
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
    pcapHandleVoid(pcapHandle_)
{
}

PcapResult Pcap::successOnZeroGeterror(int result)
{
    return PcapResult::successOnZeroLazy(result, [this](int) { return pcap_geterr(castPcap(pcapHandleVoid)); });
}

char *Pcap::pcap_geterr_wrapper() const
{
    return pcap_geterr(castPcap(pcapHandleVoid));
}

Result<int> Pcap::setTimeoutMs(int ms)
{
    return Result<int>::successOnZeroLazy(pcap_set_timeout(castPcap(pcapHandleVoid), ms),
                                          [this](int) { return pcap_geterr_wrapper(); });
}

extern "C" void worker_wrapper(unsigned char *callbackPtr,
                               const pcap_pkthdr *header,
                               const unsigned char *bytes)
{
    assert(callbackPtr != nullptr);
    assert(header != nullptr);

    const PcapCallback & callback = *reinterpret_cast<const PcapCallback *>(callbackPtr);
    callback(PcapPacket{ header->ts, header->len, { bytes, header->caplen } });
}

std::future<bool> Pcap::startLoop(PcapCallback callback, int count)
{
    return std::async(std::launch::async, [this, count, cb = std::move(callback)]() mutable {
        pcap_loop(castPcap(pcapHandleVoid), count, &worker_wrapper,
                  reinterpret_cast<unsigned char *>(std::addressof(cb)));
        return true;
    });
}

void Pcap::breakLoop()
{
    pcap_breakloop(castPcap(pcapHandleVoid));
}

Pcap::~Pcap()
{
    if (pcapHandleVoid) {
        pcap_close(castPcap(pcapHandleVoid));
    }
}

PcapResult Pcap::setImmediateMode(bool enabled)
{
    return successOnZeroGeterror(pcap_set_immediate_mode(castPcap(pcapHandleVoid), static_cast<int>(enabled)));
}

PcapResult Pcap::setSnaplen(int snaplen)
{
    return successOnZeroGeterror(pcap_set_snaplen(castPcap(pcapHandleVoid), snaplen));
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
    int compileRes = pcap_compile(castPcap(pcapHandleVoid), &prog, filterStr, static_cast<int>(optimize), netmask);
    if (compileRes != 0) {
        return PcapResult::fail(compileRes, pcap_geterr(castPcap(pcapHandleVoid)));
    }
    std::unique_ptr<bpf_program, BpfProgramDeleter> progGuard{ &prog };

    return successOnZeroGeterror(pcap_setfilter(castPcap(pcapHandleVoid), &prog));
}

PcapResult Pcap::activate()
{
    return successOnZeroGeterror(pcap_activate(castPcap(pcapHandleVoid)));
}
