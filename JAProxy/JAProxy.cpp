#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <memory>
#include <thread>

#include <boost/asio.hpp>
#include <pcap/pcap.h>

#include <JKAProto/ReliableCommandsStore.h>
#include <JKAProto/ClientConnection.h>
#include <JKAProto/ClientGameState.h>
#include <JKAProto/ClientPacketParser.h>
#include <JKAProto/ServerPacketParser.h>
#include <JKAProto/ClientEventsListener.h>
#include <JKAProto/protocol/RawPacket.h>
#include <JKAProto/protocol/ClientPacket.h>
#include <JKAProto/protocol/ServerPacket.h>
#include <JKAProto/protocol/PacketEncoder.h>
#include <JKAProto/protocol/Netchan.h>
#include <JKAProto/packets/AllConnlessPackets.h>
#include <JKAProto/packets/ConnlessPacketFactory.h>

#include "Pcap.h"
#include "ip_helpers.h"
#include "JKAListener.h"
#include "Client.h"
#include "Server.h"

bool tests()
{
    JKA::Protocol::RawPacket packet("\xFF\xFF\xFF\xFFHello World!");
    std::cout << "IsOOB: " << packet.isOOB() << std::endl;
    std::cout << "Data: " << packet.getWriteableView().subspan(packet.SEQUENCE_LEN).to_sv() << std::endl;

    auto span = packet.getWriteableViewAfterSequence();
    std::transform(span.begin(), span.end(), span.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });
    std::cout << packet.getView().to_sv().substr(packet.SEQUENCE_LEN) << std::endl;

    JKA::Q3Huffman huff{};
    JKA::ReliableCommandsStore store{};
    JKA::ClientConnection conn{};

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

        auto chan_client = JKA::Protocol::Netchan<JKA::Protocol::ServerPacketEncoder>();
        auto chan_server = JKA::Protocol::Netchan<JKA::Protocol::ClientPacketEncoder>();

        chan_server.processOutgoingPacket({ buffer.get() + 4, msg.cursize - 4 }, 22222222, huff, conn, store);
        auto rawPacket = JKA::Protocol::RawPacket({ buffer.get(), msg.cursize });
        auto decoded = chan_client.processIncomingPacket(rawPacket, huff, conn, store);

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

int main(int argc, const char *argv[])
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

    //{
    //    size_t idx = 0;
    //    for (const auto & iface : ifacesRes.result.value()) {
    //        std::cout << "[" << idx++ << "]: " << iface.name << ": " << iface.description.value_or("(no description)") << std::endl;
    //        for (const auto & addr : iface.addresses) {
    //            std::cout << "    " << addr.addr;
    //            if (addr.netmask.has_value()) {
    //                std::cout << ", netmask " << addr.netmask.value();
    //            }
    //            if (addr.broadaddr.has_value()) {
    //                std::cout << ", broadcast " << addr.broadaddr.value();
    //            }
    //            std::cout << std::endl;
    //        }
    //    }
    //}

    if (argc < 4) {
        std::cout << "Usage: JAProxy <interface idx> <server ip> <server port>" << std::endl;
        return EXIT_FAILURE;
    }

    size_t ifaceIdx = std::stoull(argv[1]);
    if (ifaceIdx >= ifacesRes.result.value().size()) {
        std::cout << "ERROR: invalid iface idx" << std::endl;
        return EXIT_FAILURE;
    }
    std::string_view targetIface = ifacesRes.result.value()[ifaceIdx].name;

    auto serverAddr = boost::asio::ip::make_address_v4(argv[2]);
    uint16_t serverPort = static_cast<uint16_t>(std::stoul(argv[3]));

    auto server = Server(serverAddr,
                         serverPort,
                         std::chrono::milliseconds(200),
                         true,
                         targetIface);

    std::cout << "Starting the loop..." << std::endl;
    auto fut = server.startLoop();
    // std::this_thread::sleep_for(std::chrono::seconds(10));
    std::cin.get();

    std::cout << "Breaking the loop..." << std::endl;
    server.breakLoop();

    std::cout << "Waiting for the worker thread to exit..." << std::endl;
    try {
        bool res = fut.get();
        std::cout << "Got " << std::boolalpha << res << " from the future. Goodbye!" << std::endl;
    } catch (const std::exception & ex) {
        std::cout << "Exception in the worker thread: " << ex.what() << std::endl;
    }
    return EXIT_SUCCESS;
}
