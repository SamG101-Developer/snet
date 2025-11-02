module;

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#undef htons

export module snet.net.socket;
import std;

namespace snet::net::internal {
#ifdef _WIN32
    using socket_t = SOCKET;
    using sockaddr_in4 = struct ::sockaddr_in4;
    using sockaddr = struct ::sockaddr;
    inline std::function socket = ::socket;
    inline std::function close_socket = ::closesocket;
    inline std::function bind = ::bind;
    inline std::function send_to = ::sendto;
    inline std::function recv_from = ::recvfrom;
    inline std::function setsockopt = ::setsockopt;
    inline std::function htons = ::htons;
    inline std::function inet_pton = ::inet_pton;
#else
    using socket_t = int;
    using sockaddr_in4 = struct ::sockaddr_in;
    using sockaddr = struct ::sockaddr;
    inline std::function socket = ::socket;
    inline std::function close_socket = ::close;
    inline std::function bind = ::bind;
    inline std::function send_to = ::sendto;
    inline std::function recv_from = ::recvfrom;
    inline std::function setsockopt = ::setsockopt;
    inline std::function htons = ::htons;
    inline std::function inet_pton = ::inet_pton;
    inline std::function inet_ntop = ::inet_ntop;
    inline std::function ntohs = ::ntohs;
#endif
    constexpr auto AF_INET4_ = AF_INET;
    constexpr auto SOCK_DGRAM_ = SOCK_DGRAM;
    constexpr auto SOL_SOCKET_ = SOL_SOCKET;
    constexpr auto SO_REUSEADDR_ = SO_REUSEADDR;
    constexpr auto IPPROTO_UDP_ = static_cast<int>(IPPROTO_UDP);
    inline struct in_addr in4addr_any = {INADDR_ANY};
}


export namespace snet::net {
    class Socket {
    public:
        Socket();
        Socket(const Socket &other) = delete;

        Socket(Socket &&other) noexcept {
            std::lock_guard lock(other.mtx);
            this->socket_fd = other.socket_fd;
            other.socket_fd = 0;
        }

        ~Socket();

    public:
        auto operator=(const Socket &other) -> Socket& = delete;

        auto operator=(Socket &&other) noexcept -> Socket& {
            if (this != &other) {
                std::scoped_lock lock(this->mtx, other.mtx);
                this->socket_fd = other.socket_fd;
                other.socket_fd = 0;
            }
            return *this;
        }

    private:
        auto init_socket() -> void;

    public:
        auto bind(std::uint16_t port) const -> void;
        auto close() -> void;
        auto send(std::span<std::uint8_t> data, std::string const &ip, std::uint16_t port) const -> void;
        auto recv() const -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t>;

    private:
        internal::socket_t socket_fd;
        std::mutex mtx;
    };
}


snet::net::Socket::Socket() {
    this->socket_fd = 0;
    this->init_socket();
}


snet::net::Socket::~Socket() {
    if (this->socket_fd != 0) { this->close(); }
}


auto snet::net::Socket::init_socket()
    -> void {
    constexpr auto opt = 1;
    this->socket_fd = internal::socket(internal::AF_INET4_, internal::SOCK_DGRAM_, internal::IPPROTO_UDP_);
    if (this->socket_fd == static_cast<internal::socket_t>(-1)) {
        throw std::system_error(errno, std::system_category(), "Failed to create socket");
    }

    if (internal::setsockopt(this->socket_fd, internal::SOL_SOCKET_, internal::SO_REUSEADDR_, &opt, sizeof(opt)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to set socket options");
    }
}


auto snet::net::Socket::bind(
    const std::uint16_t port) const
    -> void {
    // Create the address structure for IPv4.
    auto addr = internal::sockaddr_in4{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = internal::AF_INET4_;
    addr.sin_port = internal::htons(port);
    addr.sin_addr = internal::in4addr_any;

    if (internal::bind(this->socket_fd, reinterpret_cast<internal::sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to bind socket to port " + std::to_string(port));
    }
}


auto snet::net::Socket::close() -> void {
    if (this->socket_fd != 0) {
        if (internal::close_socket(this->socket_fd) < 0) {
            throw std::system_error(errno, std::system_category(), "Failed to close socket");
        }
        this->socket_fd = 0;
    }
}


auto snet::net::Socket::send(
    const std::span<std::uint8_t> data,
    std::string const &ip,
    const std::uint16_t port) const -> void {
    // Create the address structure for IPv4.
    auto addr = internal::sockaddr_in4{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = internal::AF_INET4_;
    addr.sin_port = internal::htons(port);
    if (internal::inet_pton(internal::AF_INET4_, ip.c_str(), &addr.sin_addr) <= 0) {
        throw std::system_error(errno, std::system_category(), "Invalid IP address: " + ip);
    }

    // Add a frame header specifying the length of the data (size_t, so 8 byte header).
    const auto data_size = data.size();
    auto buffer = std::vector<uint8_t>(sizeof(std::size_t) + data_size);
    std::memcpy(buffer.data(), &data_size, sizeof(std::size_t));
    std::memcpy(buffer.data() + sizeof(std::size_t), data.data(), data_size);

    // Send the data.
    const auto sent = internal::send_to(
        this->socket_fd, buffer.data(), buffer.size(), 0,
        reinterpret_cast<internal::sockaddr*>(&addr), sizeof(addr));

    if (sent < 0 or sent != static_cast<ssize_t>(buffer.size())) {
        throw std::system_error(errno, std::system_category(), "Failed to send data to " + ip + ":" + std::to_string(port));
    }
}


auto snet::net::Socket::recv() const -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t> {
    // Prepare sockaddr for sender info
    sockaddr_in src_addr{};
    socklen_t addr_len = sizeof(src_addr);

    // Create a buffer to hold the received data.
    auto header_buffer = std::vector<std::uint8_t>(65535);
    const auto recv_len = internal::recv_from(
        this->socket_fd, header_buffer.data(), header_buffer.size(), 0,
        reinterpret_cast<internal::sockaddr*>(&src_addr), &addr_len);

    if (recv_len <= 0) {
        throw std::system_error(errno, std::system_category(), "Failed to receive data");
    }

    if (static_cast<std::size_t>(recv_len) < sizeof(std::size_t)) {
        throw std::runtime_error("Received data is smaller than header size");
    }

    // Extract the data length from the header.
    auto data_size = 0uz;
    std::memcpy(&data_size, header_buffer.data(), sizeof(std::size_t));
    if (data_size + sizeof(std::size_t) != static_cast<std::size_t>(recv_len)) {
        throw std::runtime_error("Received data size does not match header length");
    }

    auto payload = std::vector<std::uint8_t>(data_size);
    std::memcpy(payload.data(), header_buffer.data() + sizeof(std::size_t), data_size);

    // Extract sender IP and port
    char ip_str[INET_ADDRSTRLEN];
    if (internal::inet_ntop(internal::AF_INET4_, &src_addr.sin_addr, ip_str, sizeof(ip_str)) == nullptr) {
        throw std::system_error(errno, std::system_category(), "Failed to convert sender IP to string");
    }
    const auto sender_ip = std::string(ip_str);
    const auto sender_port = internal::ntohs(src_addr.sin_port);
    return {std::move(payload), sender_ip, sender_port};

}
