#pragma once
#include <cinttypes>
#include <iostream>

#include <boost/asio.hpp>

#include <JKAProto/ReliableCommandsStore.h>
#include <JKAProto/ClientConnection.h>
#include <JKAProto/ClientEventsListener.h>
#include <JKAProto/ClientGameState.h>
#include <JKAProto/ClientPacketParser.h>
#include <JKAProto/ServerPacketParser.h>
#include <JKAProto/protocol/RawPacket.h>
#include <JKAProto/protocol/ClientPacket.h>
#include <JKAProto/protocol/ServerPacket.h>
#include <JKAProto/protocol/PacketEncoder.h>
#include <JKAProto/protocol/Netchan.h>
#include <JKAProto/packets/AllConnlessPackets.h>
#include <JKAProto/packets/ConnlessPacketFactory.h>
#include <JKAProto/Huffman.h>
#include <JKAProto/SharedDefs.h>

class Client {
public:
    Client(const boost::asio::ip::address_v4 & clientAddr,
           uint16_t clientQPort,
           JKA::JKAInfo info) noexcept;

    boost::asio::ip::address_v4 getAddr() const;
    uint16_t getQPort() const noexcept;
    uint16_t getNetPort() const noexcept;
    void setNetPort(uint16_t newNetPort) noexcept;

    void oobPacketFromClient(const JKA::Packets::ConnlessPacket & packet, JKA::TimePoint arriveTimePoint);
    void oobPacketFromServer(const JKA::Packets::ConnlessPacket & packet, JKA::TimePoint arriveTimePoint);

    void connfullPacketFromClient(JKA::Protocol::RawPacket && packet, JKA::TimePoint arriveTimePoint);
    void connfullPacketFromServer(JKA::Protocol::RawPacket && packet, JKA::TimePoint arriveTimePoint);

private:
    struct EvListener : public JKA::ClientEventsListener {
        EvListener(Client & cl) :
            cl(cl)
        {
        }

        virtual void onClientInfoChanged(const JKA::JKAInfo &, const JKA::JKAInfo & newInfo) override
        {
            std::string_view name = "<NO NAME>";

            auto it = newInfo.find("name");
            if (it != newInfo.end()) {
                name = it->second;
            }

            std::cout << cl.getAddr() << ":" << cl.getQPort() << " -> " << name << std::endl;
        }

        virtual void onNewUsercmd(const JKA::usercmd_t & cmd) override
        {
            if (lastMessageAcknowledged < cl.connection.messageAcknowledge) {
                lastMessageAcknowledged = cl.connection.messageAcknowledge;
                const auto & oldSnap = cl.state().snapshots[cl.connection.messageAcknowledge & JKA::PACKET_MASK];
                const auto & prevSnap = cl.state().snapshots[(cl.connection.messageAcknowledge - 1) & JKA::PACKET_MASK];
                int32_t rtt = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    cmd.arriveTime - oldSnap.arriveTime).count());
                int32_t curDiff = (cmd.serverTime - oldSnap.snap.serverTime);
                int32_t frameTime = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    cmd.arriveTime - cl.state().lastUsercmd.arriveTime).count());
                curDiff -= rtt;
                curDiff += frameTime;
                curDiff += (oldSnap.snap.serverTime - prevSnap.snap.serverTime);
                diff(cl.connection.messageAcknowledge) = curDiff;
                if (cl.connection.messageAcknowledge % DELTA_AVERAGE == 0) {
                    int32_t diffsSum = 0;
                    for (auto & diff : diffs) {
                        diffsSum += diff;
                    }

                    std::string_view name = "";

                    auto it = cl.state().info.find("name");
                    if (it != cl.state().info.end()) {
                        name = it->second;
                    }
                    std::cout << "Client ";
                    if (name.empty()) {
                        std::cout << cl.getAddr() << ":" << cl.getNetPort();
                    } else {
                        std::cout << name;
                    }
                    std::cout << " serverTime average delta: "
                        << (diffsSum / static_cast<float>(DELTA_AVERAGE)) << std::endl;
                }
            }
        }

    private:
        constexpr static size_t DELTA_AVERAGE = 100;

        Client & cl;

        int32_t lastMessageAcknowledged = 0;
        std::array<int32_t, DELTA_AVERAGE> diffs{};
        int32_t & diff(size_t seq)
        {
            return diffs[seq % DELTA_AVERAGE];
        }
    };

    JKA::ClientGameState & state() noexcept;

    static JKA::Q3Huffman huff;

    boost::asio::ip::address_v4 clientAddr{};
    uint16_t clientQPort{};
    uint16_t netPort = 0;

    JKA::ReliableCommandsStore store{};
    JKA::ClientConnection connection{};
    std::unique_ptr<JKA::ClientGameState> statePtr = std::make_unique<JKA::ClientGameState>();

    JKA::Protocol::Netchan<JKA::Protocol::ServerPacketEncoder> netchan_server{};
    JKA::Protocol::Netchan<JKA::Protocol::ClientPacketEncoder> netchan_client{};

    EvListener listener;

    JKA::ClientPacketParser clPacketParser;
    JKA::ServerPacketParser svPacketParser;
};

