#pragma once
#include <cinttypes>
#include <optional>

#include <boost/asio.hpp>
#include <JKAProto/SharedDefs.h>
#include <JKAProto/utility/Span.h>

#ifdef _MSC_VER
#include <winsock2.h>

#pragma pack(push, 1)
struct iphdr   {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl : 4;
    uint8_t version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version : 4;
    uint8_t ihl : 4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
static_assert(sizeof(iphdr) == 20);

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
static_assert(sizeof(udphdr) == 8);

#pragma pack(pop)
#else  // _MSC_VER
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif  // _MSC_VER

constexpr size_t ihl_to_bytes(size_t ihl)
{
    return ihl * 4;
}

inline const iphdr *packetToIpHeader(JKA::Utility::Span<const JKA::ByteType> rawIpData)
{
    if (rawIpData.size() < sizeof(iphdr)) {
        return nullptr;
    }

    return reinterpret_cast<const iphdr *>(rawIpData.data());
}

inline const udphdr *IpPacketToUdpHeader(JKA::Utility::Span<const JKA::ByteType> rawIpData)
{
    const iphdr *ip = packetToIpHeader(rawIpData);
    if (!ip) {
        return nullptr;
    }

    size_t offset = ihl_to_bytes(ip->ihl);
    if (offset + sizeof(udphdr) < rawIpData.size()) {
        return reinterpret_cast<const udphdr *>(rawIpData.data() + offset);
    } else {
        return nullptr;
    }
}

struct SimpleIPHeader
{
    boost::asio::ip::address_v4 source{};
    boost::asio::ip::address_v4 dest{};
    size_t headerLen{};

    static std::optional<SimpleIPHeader> fromRawIp(JKA::Utility::Span<const JKA::ByteType> rawIpData)
    {
        const iphdr *ip = packetToIpHeader(rawIpData);
        if (ip) {
            return SimpleIPHeader{
                boost::asio::ip::make_address_v4(ntohl(ip->saddr)),
                boost::asio::ip::make_address_v4(ntohl(ip->daddr)),
                ihl_to_bytes(ip->ihl)
            };
        } else {
            return {};
        }
    }
};

struct SimpleUdpHeader {
    SimpleIPHeader ip{};
    uint16_t sourcePort{};
    uint16_t destPort{};
    size_t headerLen{};

    static std::optional<SimpleUdpHeader> fromRawIp(JKA::Utility::Span<const JKA::ByteType> rawIpData)
    {
        auto ipOpt = SimpleIPHeader::fromRawIp(rawIpData);
        if (!ipOpt) {
            return {};
        }

        const udphdr *udp = IpPacketToUdpHeader(rawIpData);
        if (!udp) {
            return {};
        }

        return SimpleUdpHeader{ ipOpt.value(), ntohs(udp->source), ntohs(udp->dest), sizeof(udphdr) };
    }
};

struct SimpleUdpPacket {
    SimpleUdpHeader hdr{};
    JKA::Utility::Span<const JKA::ByteType> data;

    static std::optional<SimpleUdpPacket> fromRawIp(JKA::Utility::Span<const JKA::ByteType> rawIpData)
    {
        auto hdrOpt = SimpleUdpHeader::fromRawIp(rawIpData);
        if (!hdrOpt) {
            return {};
        }

        size_t dataOffset = hdrOpt->ip.headerLen + hdrOpt->headerLen;
        return SimpleUdpPacket{ hdrOpt.value(), rawIpData.subspan(dataOffset) };
    }
};
