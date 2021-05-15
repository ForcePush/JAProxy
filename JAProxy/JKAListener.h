#pragma once
#include <chrono>
#include <future>
#include <functional>
#include <string_view>
#include <sstream>
#include <exception>

#include <boost/asio.hpp>
#include <JKAProto/Huffman.h>
#include <JKAProto/protocol/RawPacket.h>

#include "Pcap.h"
#include "ip_helpers.h"

struct JKAListenerException : public std::runtime_error {
    JKAListenerException(std::string_view step, std::string_view message) :
        std::runtime_error(formatError(step, message))
    {
    }

private:
    static std::string formatError(std::string_view step, std::string_view message)
    {
        std::ostringstream ss;
        ss << "JKA Listener exception: step: " << step << ", error message: " << message;
        return ss.str();
    }
};

class JKAListener {
public:
    using PacketCallback = std::function<void(JKA::Protocol::RawPacket && packet, timeval ts)>;

    template<typename Rep, typename Period>
    JKAListener(const boost::asio::ip::address_v4 & serverAddr,
                uint16_t serverPort,
                const std::chrono::duration<Rep, Period> & timeout,
                bool immediateMode,
                std::string_view ifaceName = "") :
        serverAddr(serverAddr),
        serverPort(serverPort)
    {
        auto iface = std::string(ifaceName);
        if (iface.empty()) {
            auto ifacesRes = Pcap::listInterfaces();
            if (!ifacesRes) {
                throw JKAListenerException("enumerating interfaces", ifacesRes.errorStr());
            }

            if (ifacesRes->size() == 0) {
                throw JKAListenerException("enumerating interfaces", "No interfaces found");
            }

            iface = std::move(ifacesRes->front().name);
        }

        // 1. Create
        auto createRes = Pcap::create(iface.data());
        if (!createRes) {
            throw JKAListenerException("creating PCAP", createRes.errorStr());
        }
        pcap = std::move(createRes.value());

        // 2. Timeout
        throwOnResultFail("setting timeout", pcap.setTimeout(timeout));

        // 3. Immediate mode
        throwOnResultFail("setting immediate mode", pcap.setImmediateMode(immediateMode));

        // 4. Activate
        throwOnResultFail("activating pcap", pcap.activate());

        // 5. Set the datalink type
        trySetKnownDatalink(pcap);

        // 6. Set filter
        std::string filter = createFilterStr();
        throwOnResultFail("setting filter", pcap.setFilter(filter));
    }

    JKAListener(JKAListener &&) noexcept = default;
    JKAListener & operator=(JKAListener &&) noexcept = default;

    std::future<bool> startLoop(PacketCallback packetFromClient,
                                PacketCallback packetFromServer);
    void breakLoop();

private:
    enum class PacketDirection {
        FROM_CLIENT,
        FROM_SERVER,
        NOT_RELATED
    };

    std::string createFilterStr();
    void throwOnResultFail(std::string_view step, const PcapResult & res);
    void trySetKnownDatalink(Pcap & pcapObj);

    void packetArrived(const PcapPacket & packet,
                       const PacketCallback & packetFromClient,
                       const PacketCallback & packetFromServer);
    PacketDirection getPacketDirection(const SimpleUdpPacket & packet) const noexcept
    {
        if (packet.hdr.ip.dest == serverAddr && packet.hdr.destPort == serverPort) {
            return PacketDirection::FROM_CLIENT;
        } else if (packet.hdr.ip.source == serverAddr && packet.hdr.sourcePort == serverPort) {
            return PacketDirection::FROM_SERVER;
        } else {
            return PacketDirection::NOT_RELATED;
        }
    }

    static JKA::Huffman globalHuff;

    Pcap pcap{};
    boost::asio::ip::address_v4 serverAddr{};
    uint16_t serverPort{};
};

