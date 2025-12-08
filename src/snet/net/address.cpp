export module snet.net.address;
import std;
import sys;


export namespace snet::net {
    auto get_private_ipv4_address()
        -> std::string;
}


auto snet::net::get_private_ipv4_address() -> std::string {
    auto ifap = static_cast<sys::ifaddrs*>(nullptr);
    if (sys::getifaddrs(&ifap) != 0) {
        return {};
    }

    for (auto ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != sys::AF_INET) {
            continue;
        }

        // Skip loopback and down interfaces
        if (std::string(ifa->ifa_name) == "lo" || !(ifa->ifa_flags & sys::IFF_UP)) {
            continue;
        }

        char ip_str[sys::INET_ADDRSTRLEN];
        const auto *sa = reinterpret_cast<sys::sockaddr_in*>(ifa->ifa_addr);
        sys::inet_ntop(sys::AF_INET, &sa->sin_addr, ip_str, sys::INET_ADDRSTRLEN);

        if (std::string(ip_str) != "127.0.0.1") {
            const auto result = ip_str;
            sys::freeifaddrs(ifap);
            return {result};
        }
    }

    sys::freeifaddrs(ifap);
    return {};
}
