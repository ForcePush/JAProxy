#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <memory>
#include <thread>

#include <boost/asio.hpp>
#include <pcap/pcap.h>

#include <JKAProto/protocol/RawPacket.h>
#include <JKAProto/protocol/ClientPacket.h>
#include <JKAProto/protocol/ServerPacket.h>
#include <JKAProto/protocol/State.h>
#include <JKAProto/protocol/PacketEncoder.h>
#include <JKAProto/protocol/Netchan.h>
#include <JKAProto/packets/AllConnlessPackets.h>
#include <JKAProto/packets/ConnlessPacketFactory.h>

#include "Pcap.h"
#include "ip_helpers.h"
#include "JKAListener.h"

bool tests()
{
    JKA::Protocol::RawPacket packet("\xFF\xFF\xFF\xFFHello World!");
    std::cout << "IsOOB: " << packet.isOOB() << std::endl;
    std::cout << "Data: " << packet.getWriteableView().subspan(packet.SEQUENCE_LEN).to_sv() << std::endl;

    auto span = packet.getWriteableViewAfterSequence();
    std::transform(span.begin(), span.end(), span.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });
    std::cout << packet.getView().to_sv().substr(packet.SEQUENCE_LEN) << std::endl;

    JKA::Q3Huffman huff{};
    constexpr size_t BUF_SIZE = 8192;

    {
        auto buffer = std::make_unique<JKA::ByteType[]>(BUF_SIZE);
        JKA::Protocol::CompressedMessage msg(huff, buffer.get(), 0, BUF_SIZE);
        msg.writeOOB<32>(22222222);
        msg.writeLong(0x1f);
        msg.writeString("Hello, World!");

        auto msgRead = JKA::Protocol::CompressedMessage(huff, buffer.get(), msg.cursize, BUF_SIZE);
        auto seq = msgRead.readOOB<32>();
        auto mack = msgRead.readLong();
        auto str = msgRead.readString();
        std::cout << "Seq: " << seq << std::endl;
        std::cout << "Mack: " << mack << std::endl;
        std::cout << "String: " << str << std::endl;
    }

    {
        std::cout << std::endl;
        std::cout << "Encode-decode" << std::endl;

        auto buffer = std::make_unique<JKA::ByteType[]>(BUF_SIZE);
        JKA::Protocol::CompressedMessage msg(huff, buffer.get(), 0, BUF_SIZE);
        msg.writeOOB<32>(22222222);  // Sequence
        msg.writeLong(12345678);     // ReliableAcknowledge
        msg.writeString("Hello, World!");

        auto chan_client = JKA::Protocol::Netchan<JKA::Protocol::ServerPacketEncoder>(1234);
        auto chan_server = JKA::Protocol::Netchan<JKA::Protocol::ClientPacketEncoder>(1234);

        chan_server.processOutgoingPacket({ buffer.get() + 4, msg.cursize - 4 }, 22222222, huff);
        auto rawPacket = JKA::Protocol::RawPacket({ buffer.get(), msg.cursize });
        auto decoded = chan_client.processIncomingPacket(rawPacket, huff);

        auto seq = decoded->sequence;
        auto rack = decoded->reliableAcknowledge;
        auto str = decoded->message.readString();
        std::cout << "Seq: " << seq << std::endl;
        std::cout << "Mack: " << rack << std::endl;
        std::cout << "String: " << str << std::endl;
    }

    return true;
}

JKA::Huffman globalHuff{};

void packetListener(const PcapPacket & packet)
{
    auto udpOpt = SimpleUdpPacket::fromRawIp(JKA::Utility::Span(packet.data));
    if (!udpOpt) {
        std::cout << "INVALID UDP PACKET" << std::endl;
        return;
    }
    auto & udp = udpOpt.value();

    JKA::Protocol::RawPacket jkaPacket{ std::string(udp.data.to_sv()) };
    if (jkaPacket.isOOB()) {
        std::cout << "[" << packet.ts.tv_sec
            << ":" << packet.ts.tv_usec << "]: "
            << udp.hdr.ip.source << ":" << udp.hdr.sourcePort << " -> "
            << udp.hdr.ip.dest << ":" << udp.hdr.destPort << "; ";

        auto connlessPacket = JKA::Packets::ConnlessPacketFactory::parsePacket(jkaPacket.getData());
        if (!connlessPacket) {
            std::cout << "INVALID OOB PACKET: " << jkaPacket.getData();
            return;
        }
        std::cout << connlessPacket->getName();
        if (connlessPacket->getType() == JKA::CLS_CONNECT) {
            auto & connectPacket = dynamic_cast<JKA::Packets::Connect &>(*connlessPacket);
            std::cout << ": " << globalHuff.decompress(connectPacket.getData());
        }
        std::cout << std::endl;
    }
}

int main()
{
    if (!tests()) {
        return EXIT_FAILURE;
    }

    auto initRes = Pcap::initialize();
    if (!initRes) {
        std::cerr << "Pcap initialization failed: " << initRes.errorMessage.value_or("(no error message)") << std::endl;
        return EXIT_FAILURE;
    } else {
        std::cout << "Pcap initialized." << std::endl;
    }

    auto ifacesRes = Pcap::listInterfaces();
    if (!ifacesRes) {
        std::cerr << "Cannot get interfaces: " << ifacesRes.errorMessage.value_or("(no error message)") << std::endl;
        return EXIT_FAILURE;
    } else {
        std::cout << "Got " << ifacesRes.result.value().size() << " interfaces:" << std::endl;
    }

    for (const auto & iface : ifacesRes.result.value()) {
        std::cout << iface.name << ": " << iface.description.value_or("(no description)") << std::endl;
        for (const auto & addr : iface.addresses) {
            std::cout << "    " << addr.addr;
            if (addr.netmask.has_value()) {
                std::cout << ", netmask " << addr.netmask.value();
            }
            if (addr.broadaddr.has_value()) {
                std::cout << ", broadcast " << addr.broadaddr.value();
            }
            std::cout << std::endl;
        }
    }
    
    const auto & targetIface = ifacesRes.result.value()[3];
    auto listener = JKAListener(boost::asio::ip::make_address_v4("127.0.0.1"),
                                29072,
                                std::chrono::milliseconds(200),
                                true,
                                targetIface.name);
    std::cout << "Starting the loop..." << std::endl;
    auto fut = listener.startLoop();
    // std::this_thread::sleep_for(std::chrono::seconds(10));
    std::cin.get();

    std::cout << "Breaking the loop..." << std::endl;
    listener.breakLoop();

    std::cout << "Waiting for the worker thread to exit..." << std::endl;
    bool res = fut.get();
    std::cout << "Got " << std::boolalpha << res << " from the future. Goodbye!" << std::endl;

    return EXIT_SUCCESS;
}
