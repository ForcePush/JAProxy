#pragma once
#include <chrono>
#include <map>

#include <boost/asio.hpp>
#include <JKAProto/packets/Connect.h>
#include <JKAProto/protocol/RawPacket.h>

#include "Client.h"
#include "JKAListener.h"

class Server {
public:
    template<typename Rep, typename Period>
    Server(const boost::asio::ip::address_v4 & serverAddr,
           uint16_t serverPort,
           const std::chrono::duration<Rep, Period> & timeout,
           bool immediateMode,
           std::string_view ifaceName = "") :
        serverAddr(serverAddr),
        serverPort(serverPort),
        listener(serverAddr, serverPort, timeout, immediateMode, ifaceName)
    {
    }

    std::future<bool> startLoop();
    void breakLoop();

private:
    static JKA::Huffman huffman;

    using QportClientsMap = std::map<uint16_t, Client>;
    using ClientsMap = std::map<boost::asio::ip::address_v4, QportClientsMap>;

    void onPacketFromClient(const boost::asio::ip::udp::endpoint & from,
                            const boost::asio::ip::udp::endpoint & to,
                            JKA::Protocol::RawPacket && packet,
                            JKA::TimePoint arriveTimePoint);
    void onPacketFromServer(const boost::asio::ip::udp::endpoint & from,
                            const boost::asio::ip::udp::endpoint & to,
                            JKA::Protocol::RawPacket && packet,
                            JKA::TimePoint arriveTimePoint);

    Client *onConnectPacketFromClient(const boost::asio::ip::udp::endpoint & from, const JKA::Packets::Connect & packet);

    Client *createClient(const boost::asio::ip::address_v4 & from, JKA::JKAInfo && info);
    Client *findClient(const boost::asio::ip::address_v4 & from, uint16_t qport);
    void removeClient(const boost::asio::ip::address_v4 & from, uint16_t qport);

    boost::asio::ip::address_v4 serverAddr{};
    uint16_t serverPort{};

    JKAListener listener;

    ClientsMap clients{};
};

