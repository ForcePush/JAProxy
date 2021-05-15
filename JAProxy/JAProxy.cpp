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

    {
        size_t idx = 0;
        for (const auto & iface : ifacesRes.result.value()) {
            std::cout << "[" << idx++ << "]: " << iface.name << ": " << iface.description.value_or("(no description)") << std::endl;
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
    }


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
    uint16_t serverPort = std::stoul(argv[3]);

    auto listener = JKAListener(serverAddr,
                                serverPort,
                                std::chrono::milliseconds(200),
                                true,
                                targetIface);

    JKA::Q3Huffman huff{};
    JKA::ReliableCommandsStore store{};
    JKA::ClientConnection connection{};
    std::unique_ptr<JKA::ClientGameState> statePtr = std::make_unique<JKA::ClientGameState>();
    JKA::ClientGameState & state = *statePtr;

    JKA::Protocol::Netchan<JKA::Protocol::ServerPacketEncoder> netchan_server;
    JKA::Protocol::Netchan<JKA::Protocol::ClientPacketEncoder> netchan_client;

    constexpr static size_t DELTA_AVERAGE = 100;
    constexpr static bool SHOW_PACKETS = false;

    struct EvListener : public JKA::ClientEventsListener {
        EvListener(JKA::ClientGameState & state, JKA::ClientConnection & connection) :
            state(state),
            connection(connection)
        {
        }

        virtual void onClientInfoChanged(const JKA::JKAInfo &, const JKA::JKAInfo & newInfo) override
        {
            std::cout << "New userinfo:";
            for (const auto & [k, v] : newInfo) {
                std::cout << std::endl << k << ": " << v;
            }
            std::cout << std::endl;
        }

        virtual void onServerReliableCommand(const JKA::CommandParser::Command & cmd) override
        {
            std::cout << "Server command: " << cmd.name << " " << cmd.concat() << std::endl;
        }

        virtual void onClientReliableCommand(int32_t, const JKA::CommandParser::Command & cmd) override
        {
            std::cout << "Client command: " << cmd.name << " " << cmd.concat() << std::endl;
        }

        virtual void onNewUsercmd(const JKA::usercmd_t & cmd) override
        {
            if (lastMessageAcknowledged != connection.messageAcknowledge) {
                lastMessageAcknowledged = connection.messageAcknowledge;
                const auto & oldSnap = state.snapshots[connection.messageAcknowledge & JKA::PACKET_MASK];
                const auto & prevSnap = state.snapshots[(connection.messageAcknowledge - 1) & JKA::PACKET_MASK];
                int32_t rtt = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    cmd.arriveTime - oldSnap.arriveTime).count());
                int32_t curDiff = (cmd.serverTime - oldSnap.snap.serverTime);
                int32_t frameTime = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    cmd.arriveTime - state.lastUsercmd.arriveTime).count());
                curDiff -= rtt;
                curDiff += frameTime;
                curDiff += (oldSnap.snap.serverTime - prevSnap.snap.serverTime);
                diff(connection.messageAcknowledge) = curDiff;
                // std::cout << "Snapshot " << connection.messageAcknowledge << "; rtt " << rtt << "; frameTime " << frameTime << "; diff " << curDiff << std::endl;
                if (connection.messageAcknowledge % DELTA_AVERAGE == 0) {
                    int32_t diffsSum = 0;
                    for (auto & diff : diffs) {
                        diffsSum += diff;
                    }
                    std::cout << "Client serverTime average delta: " << (diffsSum / static_cast<float>(DELTA_AVERAGE)) << std::endl;
                }
            }
        }

        JKA::ClientGameState & state;
        JKA::ClientConnection & connection;

        int32_t lastMessageAcknowledged = 0;
        std::array<int32_t, DELTA_AVERAGE> diffs{};
        int32_t & diff(size_t seq)
        {
            return diffs[seq % DELTA_AVERAGE];
        }
    };

    EvListener evListener{state, connection};

    JKA::ClientPacketParser clPacketParser(evListener, store, connection, state);
    JKA::ServerPacketParser svPacketParser(evListener, store, connection, state);

    auto packetFromClient = [&](JKA::Protocol::RawPacket && packet, timeval ts) {
        if (packet.isConnless()) {
            auto parsedPacket = JKA::Packets::ConnlessPacketFactory::parsePacket(packet.getData());
            if (parsedPacket) {
                svPacketParser.handleOobPacketFromClient(*parsedPacket);
                clPacketParser.handleOobPacketFromClient(*parsedPacket);
            }
        } else {  // Connfull
            auto decodedPacket = netchan_client.processIncomingPacket(packet, huff, connection, store);
            if (decodedPacket) {
                if (SHOW_PACKETS) {
                    std::cout << "CLIENT -> SERVER (" << decodedPacket->message.to_span().size() << " bytes): seq " << decodedPacket->sequence
                    << ", qport " << decodedPacket->qport
                    << ", serverId " << decodedPacket->serverId
                    << ", mAck " << decodedPacket->messageAcknowledge
                    << ", relAck " << decodedPacket->reliableAcknowledge
                    << std::endl;
                }
                auto arriveTimeUnix = std::chrono::seconds(ts.tv_sec) + std::chrono::microseconds(ts.tv_usec);
                auto arriveTimeUnixCasted = std::chrono::duration_cast<JKA::TimePoint::duration>(arriveTimeUnix);
                auto arriveTimePoint = JKA::TimePoint(arriveTimeUnixCasted);
                clPacketParser.handleConnfullPacketFromClient(decodedPacket.value(), arriveTimePoint);
            }
        }
    };

    auto packetFromServer = [&](JKA::Protocol::RawPacket && packet, timeval ts) {
        if (packet.isConnless()) {
            auto parsedPacket = JKA::Packets::ConnlessPacketFactory::parsePacket(packet.getData());
            if (parsedPacket) {
                svPacketParser.handleOobPacketFromServer(*parsedPacket);
                clPacketParser.handleOobPacketFromServer(*parsedPacket);
            }
        } else {  // Connfull
            auto decodedPacket = netchan_server.processIncomingPacket(packet, huff, connection, store);
            if (decodedPacket) {
                if (SHOW_PACKETS) {
                    std::cout << "SERVER -> CLIENT (" << decodedPacket->message.to_span().size() << " bytes): seq " << decodedPacket->sequence
                        << ", relAck " << decodedPacket->reliableAcknowledge
                        << std::endl;
                }
                auto arriveTimeUnix = std::chrono::seconds(ts.tv_sec) + std::chrono::microseconds(ts.tv_usec);
                auto arriveTimeUnixCasted = std::chrono::duration_cast<JKA::TimePoint::duration>(arriveTimeUnix);
                auto arriveTimePoint = JKA::TimePoint(arriveTimeUnixCasted);
                svPacketParser.handleConnfullPacketFromServer(decodedPacket.value(), arriveTimePoint);
            }
        }
    };

    std::cout << "Starting the loop..." << std::endl;
    auto fut = listener.startLoop(std::move(packetFromClient), std::move(packetFromServer));
    // std::this_thread::sleep_for(std::chrono::seconds(10));
    std::cin.get();

    std::cout << "Breaking the loop..." << std::endl;
    listener.breakLoop();

    std::cout << "Waiting for the worker thread to exit..." << std::endl;
    try {
        bool res = fut.get();
        std::cout << "Got " << std::boolalpha << res << " from the future. Goodbye!" << std::endl;
    } catch (const std::exception & ex) {
        std::cout << "Exception in the worker thread: " << ex.what() << std::endl;
    }
    return EXIT_SUCCESS;
}
