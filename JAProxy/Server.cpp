#include "Server.h"
#include <functional>
#include <future>
#include <utility>

JKA::Huffman Server::huffman;

std::future<bool> Server::startLoop()
{
    return std::async(std::launch::async, [this]() mutable {
        return listener.startLoopBlocking(
            [this](const boost::asio::ip::udp::endpoint & from,
                   const boost::asio::ip::udp::endpoint & to,
                   JKA::Protocol::RawPacket && packet,
                   JKA::TimePoint arriveTimePoint) {
                onPacketFromClient(from, to, std::move(packet), arriveTimePoint);
        },  [this](const boost::asio::ip::udp::endpoint & from,
                   const boost::asio::ip::udp::endpoint & to,
                   JKA::Protocol::RawPacket && packet,
                   JKA::TimePoint arriveTimePoint) {
                onPacketFromServer(from, to, std::move(packet), arriveTimePoint);
        });
    });
}

void Server::breakLoop()
{
    listener.breakLoop();
}

void Server::onPacketFromClient(const boost::asio::ip::udp::endpoint & from,
                                const boost::asio::ip::udp::endpoint & to,
                                JKA::Protocol::RawPacket && packet,
                                JKA::TimePoint arriveTimePoint)
{
    static_cast<void>(to);

    if (packet.isConnless()) {
        auto connlessPacket = JKA::Packets::ConnlessPacketFactory::parsePacket(packet.getData());
        if (!connlessPacket) {
            return;
        }

        JKA::ConnlessType packetType = connlessPacket->getType();
        if (packetType == JKA::CLS_CONNECT) {
            onConnectPacketFromClient(from, static_cast<const JKA::Packets::Connect &>(*connlessPacket));
        }
    } else {  // Connfull
        uint16_t qport = packet.getQport();
        Client *cl = findClient(from.address().to_v4(), qport);
        if (cl) {
            cl->connfullPacketFromClient(std::move(packet), arriveTimePoint);
        }
    }
}

void Server::onPacketFromServer(const boost::asio::ip::udp::endpoint & from,
                                const boost::asio::ip::udp::endpoint & to,
                                JKA::Protocol::RawPacket && packet,
                                JKA::TimePoint arriveTimePoint)
{
    static_cast<void>(from);

    auto addrTo = to.address().to_v4();
    auto portTo = to.port();
    auto it = clients.find(addrTo);
    if (it == clients.end()) {
        return;
    }

    Client *clPtr = nullptr;
    for (auto & [qport, client] : it->second) {
        if (client.getNetPort() == portTo) {
            clPtr = std::addressof(client);
            break;
        }
    }

    if (clPtr == nullptr) {
        return;
    }

    if (packet.isConnless()) {
        auto connlessPacket = JKA::Packets::ConnlessPacketFactory::parsePacket(packet.getData());
        if (!connlessPacket) {
            return;
        }
        clPtr->oobPacketFromServer(*connlessPacket, arriveTimePoint);
    } else {  // Connfull
        clPtr->connfullPacketFromServer(std::move(packet), arriveTimePoint);
    }
}

Client *Server::onConnectPacketFromClient(const boost::asio::ip::udp::endpoint & from, const JKA::Packets::Connect & packet)
{
    std::string clientInfoStr = huffman.decompress(packet.getData());
    auto clientInfoView = std::string_view(clientInfoStr);

    // Remove the first and the last characters (")
    if (clientInfoView.size() <= 2) {
        return nullptr;
    }

    clientInfoView = clientInfoView.substr(1, clientInfoView.size() - 2);
    auto clientInfo = JKA::JKAInfo::fromInfostring(clientInfoView);
    Client *cl = createClient(from.address().to_v4(), std::move(clientInfo));
    if (cl) {
        cl->setNetPort(from.port());
    }
    return cl;
}

Client *Server::createClient(const boost::asio::ip::address_v4 & from, JKA::JKAInfo && info)
{
    auto it = info.find("qport");
    if (it == info.end()) {
        return nullptr;
    }

    uint16_t qport = 0;
    try {
        qport = static_cast<uint16_t>(std::stoul(it->second));
    } catch (const std::invalid_argument &) {
        return nullptr;
    } catch (const std::out_of_range &) {
        return nullptr;
    }

    removeClient(from, qport);
    return std::addressof(clients[from].try_emplace(qport, from, qport, std::move(info)).first->second);
}

Client *Server::findClient(const boost::asio::ip::address_v4 & from, uint16_t qport)
{
    auto fromIt = clients.find(from);
    if (fromIt == clients.end()) {
        return nullptr;
    }

    auto & qportMap = fromIt->second;
    auto qportIt = qportMap.find(qport);
    if (qportIt == qportMap.end()) {
        return nullptr;
    }

    return std::addressof(qportIt->second);
}

void Server::removeClient(const boost::asio::ip::address_v4 & from, uint16_t qport)
{
    auto fromIt = clients.find(from);
    if (fromIt == clients.end()) {
        return;
    }

    auto & qportMap = fromIt->second;
    qportMap.erase(qport);
}
