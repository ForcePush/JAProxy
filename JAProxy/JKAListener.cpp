#include "JKAListener.h"
#include <iostream>

#include <boost/asio.hpp>

#include <JKAProto/protocol/ClientPacket.h>
#include <JKAProto/protocol/ServerPacket.h>
#include <JKAProto/protocol/PacketEncoder.h>
#include <JKAProto/protocol/Netchan.h>
#include <JKAProto/packets/AllConnlessPackets.h>
#include <JKAProto/packets/ConnlessPacketFactory.h>

JKA::Huffman JKAListener::globalHuff{};

bool JKAListener::startLoopBlocking(PacketCallback packetFromClient,
                                    PacketCallback packetFromServer)
{
    return pcap.startLoopIPBlocking([this,
                                    pFromC = std::move(packetFromClient),
                                    pFromS = std::move(packetFromServer)](const PcapPacket & packet) {
        packetArrived(packet, pFromC, pFromS);
    }).isSuccess();
}

std::future<bool> JKAListener::startLoop(PacketCallback packetFromClient,
                                         PacketCallback packetFromServer)
{
    return std::async(std::launch::async, [this,
                                           pFromC = std::move(packetFromClient),
                                           pFromS = std::move(packetFromServer)]() mutable {
        return startLoopBlocking(std::move(pFromC), std::move(pFromS));
    });
}

void JKAListener::breakLoop()
{
    pcap.breakLoop();
}

std::string JKAListener::createFilterStr()
{
    std::ostringstream filter;
    filter << "udp and ((dst " << serverAddr
        << " and dst port " << serverPort << ") or (src "
        << serverAddr << " and src port " << serverPort << "))";
    return filter.str();
}

void JKAListener::throwOnResultFail(std::string_view step, const PcapResult & res)
{
    if (!res) {
        throw JKAListenerException(step, res.errorStr());
    }
}

void JKAListener::trySetKnownDatalink(Pcap & pcapObj)
{
    if (pcapObj.isDatalinkKnown(pcapObj.getDatalink())) {
        return;
    }

    auto supportedDatalinks = pcapObj.getSupportedDatalinks();
    if (!supportedDatalinks) {
        throw JKAListenerException("getting supported datalinks", supportedDatalinks.errorStr());
    }

    for (auto it = supportedDatalinks->begin(); it != supportedDatalinks->end(); it++) {
        if (pcapObj.isDatalinkKnown(*it)) {
            throwOnResultFail("setting supported datalink", pcapObj.setDatalink(*it));
            return;
        }
    }

    throw JKAListenerException("getting supported datalinks", "no known supported datalinks");
}

void JKAListener::packetArrived(const PcapPacket & packet,
                                const PacketCallback & packetFromClient,
                                const PacketCallback & packetFromServer)
{
    auto udpOpt = SimpleUdpPacket::fromRawIp(JKA::Utility::Span(packet.data));
    if (!udpOpt) JKA_UNLIKELY {
        return;  // Invalid packet
    }

    auto & udp = udpOpt.value();
    PacketDirection packetDir = getPacketDirection(udp);

    auto from = boost::asio::ip::udp::endpoint(udp.hdr.ip.source, udp.hdr.sourcePort);
    auto to   = boost::asio::ip::udp::endpoint(udp.hdr.ip.dest,   udp.hdr.destPort  );

    auto arriveTimeUnix = std::chrono::seconds(packet.ts.tv_sec) + std::chrono::microseconds(packet.ts.tv_usec);
    auto arriveTimeUnixCasted = std::chrono::duration_cast<JKA::TimePoint::duration>(arriveTimeUnix);
    auto arriveTimePoint = JKA::TimePoint(arriveTimeUnixCasted);

    switch (packetDir) 	{
    case JKAListener::PacketDirection::FROM_CLIENT:
    {
        packetFromClient(from, to, JKA::Protocol::RawPacket(std::string(udp.data.to_sv())), arriveTimePoint);
        break;
    }
    case JKAListener::PacketDirection::FROM_SERVER:
    {
        packetFromServer(from, to, JKA::Protocol::RawPacket(std::string(udp.data.to_sv())), arriveTimePoint);
        break;
    }
    case JKAListener::PacketDirection::NOT_RELATED: JKA_UNLIKELY
    {
        break;
    }
    }
}
