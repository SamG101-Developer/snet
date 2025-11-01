module;

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
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


auto snet::net::Socket::init_socket() -> void {
    constexpr auto opt = 1;
    this->socket_fd = internal::socket(internal::AF_INET4_, internal::SOCK_DGRAM_, internal::IPPROTO_UDP_);
    internal::setsockopt(this->socket_fd, internal::SOL_SOCKET_, internal::SO_REUSEADDR_, &opt, sizeof(opt));
}


auto snet::net::Socket::bind(const std::uint16_t port) const -> void {
    auto addr = internal::sockaddr_in4{};
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = internal::AF_INET4_;
    addr.sin_port = internal::htons(port);
    addr.sin_addr = internal::in4addr_any;

    internal::bind(this->socket_fd, reinterpret_cast<internal::sockaddr*>(&addr), sizeof(addr));
}


auto snet::net::Socket::close() -> void {
    if (this->socket_fd != 0) {
        internal::close_socket(this->socket_fd);
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

    // Set the address family, port and IP address.
    addr.sin_family = internal::AF_INET4_;
    addr.sin_port = internal::htons(port);
    internal::inet_pton(internal::AF_INET4_, ip.c_str(), &addr.sin_addr);

    // Add a frame header specifying the length of the data (size_t, so 8 byte header).
    const auto data_size = data.size();
    auto buffer = std::vector<uint8_t>(data.size() + sizeof(std::size_t));
    std::memcpy(buffer.data(), &data_size, sizeof(std::size_t));
    std::memcpy(buffer.data() + sizeof(std::size_t), data.data(), data.size());

    // Lock the mutex to ensure thread safety, and send the data.
    internal::send_to(
        this->socket_fd, data.data(), data.size(), 0, reinterpret_cast<internal::sockaddr*>(&addr), sizeof(addr));
}


auto snet::net::Socket::recv() const -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t> {
    // Create a buffer to hold the received data.
    // auto header_buffer = std::vector<std::uint8_t>(2);

    // Receive the header frame to determine the length of the data.
    // internal::recv_from(this->socket_fd, header_buffer.data(), sizeof(std::size_t), 0, nullptr, nullptr);
    // const auto msg_len = *reinterpret_cast<std::size_t*>(header_buffer.data());

    // Prepare sockaddr for sender info
    sockaddr_in src_addr{};
    socklen_t addr_len = sizeof(src_addr);

    // Receive the actual data based on the length specified in the header.
    auto buffer = std::vector<std::uint8_t>(4094);
    const auto received = internal::recv_from(this->socket_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&src_addr), &addr_len);
    if (received < 0) {
        return {};
    }

    buffer.resize(received);
    char addr_str[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &src_addr.sin_addr, addr_str, sizeof(addr_str)) == nullptr) {
        return {};
    }

    const auto port = ntohs(src_addr.sin_port);
    return {buffer, std::string(addr_str), static_cast<std::uint16_t>(port)};

    // internal::recv_from(
    //     this->socket_fd, buffer.data(), static_cast<std::int32_t>(buffer.size()), 0, nullptr, nullptr);
    // return buffer;
}
