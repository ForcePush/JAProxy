#include <cstdlib>
#include <iostream>
#include <thread>

#include <boost/asio.hpp>

#include "Pcap.h"

int main()
{
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
                std::cout << ", boardcast " << addr.broadaddr.value();
            }
            std::cout << std::endl;
        }
    }
    
    const auto & targetIface = ifacesRes.result.value()[1];
    auto createRes = Pcap::create(targetIface);
    if (!createRes) {
        std::cerr << "Cannot create Pcap: " << createRes.errorMessage.value_or("(no error message)") << std::endl;
        return EXIT_FAILURE;
    } else {
        std::cout << "Pcap on " << targetIface.name << " created." << std::endl;
    }

    auto & pcapObj = createRes.result.value();
    pcapObj.setImmediateMode(true);
    auto activateRes = pcapObj.activate();
    if (!activateRes) {
        std::cerr << "Cannot activate Pcap: " << createRes.errorMessage.value_or("(no error message)") << std::endl;
        return EXIT_FAILURE;
    } else {
        std::cout << "Pcap activated." << std::endl;
    }

    auto filterRes = pcapObj.setFilter("udp and dst port 29071");
    if (!filterRes) {
        std::cerr << "Cannot set filter: " << filterRes.errorMessage.value_or("no error message") << std::endl;
        return EXIT_FAILURE;
    } else {
        std::cout << "Filter set." << std::endl;
    }

    std::cout << "Starting the loop..." << std::endl;
    auto fut = pcapObj.startLoop([](const PcapPacket & packet) {
        std::cout << "[" << packet.ts.tv_sec
            << ":" << packet.ts.tv_usec << "]: "
            << packet.data.size() << " bytes packet arrived" << std::endl;
    });
    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::cout << "Breaking the loop..." << std::endl;
    pcapObj.breakLoop();

    std::cout << "Waiting for the worker thread to exit..." << std::endl;
    fut.wait();

    return EXIT_SUCCESS;
}
