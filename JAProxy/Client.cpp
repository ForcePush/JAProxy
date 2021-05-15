#include "Client.h"

JKA::Q3Huffman Client::huff{};

Client::Client(const boost::asio::ip::address_v4 & clientAddr,
               uint16_t clientQPort,
               JKA::JKAInfo info) noexcept :
    clientAddr(clientAddr),
    clientQPort(clientQPort),
    listener(*this),
    clPacketParser(listener, store, connection, state()),
    svPacketParser(listener, store, connection, state())
{
    svPacketParser.connectSent(std::move(info));
}

boost::asio::ip::address_v4 Client::getAddr() const
{
    return clientAddr;
}

uint16_t Client::getQPort() const noexcept
{
    return clientQPort;
}

uint16_t Client::getNetPort() const noexcept
{
    return netPort;
}

void Client::setNetPort(uint16_t newNetPort) noexcept
{
    netPort = newNetPort;
}

void Client::oobPacketFromClient(const JKA::Packets::ConnlessPacket & packet, JKA::TimePoint)
{
    svPacketParser.handleOobPacketFromClient(packet);
    clPacketParser.handleOobPacketFromClient(packet);
}

void Client::oobPacketFromServer(const JKA::Packets::ConnlessPacket & packet, JKA::TimePoint)
{
    svPacketParser.handleOobPacketFromServer(packet);
    clPacketParser.handleOobPacketFromServer(packet);
}

void Client::connfullPacketFromClient(JKA::Protocol::RawPacket && packet, JKA::TimePoint arriveTimePoint)
{
    auto decodedPacket = netchan_client.processIncomingPacket(packet, huff, connection, store);
    if (decodedPacket) {
        clPacketParser.handleConnfullPacketFromClient(decodedPacket.value(), arriveTimePoint);
    }
}

void Client::connfullPacketFromServer(JKA::Protocol::RawPacket && packet, JKA::TimePoint arriveTimePoint)
{
    auto decodedPacket = netchan_server.processIncomingPacket(packet, huff, connection, store);
    if (decodedPacket) {
        svPacketParser.handleConnfullPacketFromServer(decodedPacket.value(), arriveTimePoint);
    }
}

JKA::ClientGameState & Client::state() noexcept
{
    return *statePtr;
}
