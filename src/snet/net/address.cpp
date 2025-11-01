module;
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>


export module snet.net.address;
import std;


export namespace snet::net {
    auto get_private_ipv4_address()
        -> std::string;
}


auto snet::net::get_private_ipv4_address() -> std::string {
    auto ifap = static_cast<ifaddrs*>(nullptr);
    if (getifaddrs(&ifap) != 0) {
        return {};
    }

    for (auto ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        // Skip loopback and down interfaces
        if (std::string(ifa->ifa_name) == "lo" || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        const auto *sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &sa->sin_addr, ip_str, INET_ADDRSTRLEN);

        if (std::string(ip_str) != "127.0.0.1") {
            const auto result = ip_str;
            freeifaddrs(ifap);
            return {result};
        }
    }

    freeifaddrs(ifap);
    return {};
}
