module;
#include <cerrno>


export module snet.net.socket;
import std;
import sys;


export namespace snet::net {
    class Socket {
    protected:
        sys::socket_t socket_fd;
        std::mutex mtx;

        explicit Socket(
            std::int32_t family = sys::AF_INET,
            std::int32_t type = sys::SOCK_DGRAM,
            std::int32_t protocol = sys::IPPROTO_UDP,
            sys::socket_t fd = -1);

    public:
        Socket(const Socket &other) = delete;
        Socket(Socket &&other) noexcept;
        auto operator=(const Socket &other) -> Socket& = delete;
        auto operator=(Socket &&other) noexcept -> Socket&;
        ~Socket();

        auto bind(std::uint16_t port) const -> void;
        auto close() -> void;
        [[nodiscard]] auto fileno() const -> sys::socket_t { return socket_fd; }
    };


    template <typename S>
        requires std::derived_from<S, Socket>
    auto socket_pair() -> std::pair<S, S>;
}


snet::net::Socket::Socket(
    const std::int32_t family,
    const std::int32_t type,
    const std::int32_t protocol,
    const sys::socket_t fd) :
    socket_fd(fd) {

    // Create a socket with a new descriptor if one is not provided.
    if (socket_fd < 0) {
        socket_fd = sys::socket(family, type, protocol);
    }

    // If socket creation failed, throw an error.
    if (socket_fd == static_cast<sys::socket_t>(-1)) {
        throw std::system_error(errno, std::system_category(), "Failed to create socket");
    }

    // Set socket options standard for all sockets.
    constexpr auto opt = 1;
    if (sys::setsockopt(socket_fd, sys::SOL_SOCKET, sys::SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to set socket options");
    }
}


snet::net::Socket::Socket(
    Socket &&other) noexcept {
    std::lock_guard lock(other.mtx);
    socket_fd = other.socket_fd;
    other.socket_fd = -1;
}


auto snet::net::Socket::operator=(
    Socket &&other) noexcept
    -> Socket& {
    if (this != &other) {
        std::scoped_lock lock(mtx, other.mtx);
        socket_fd = other.socket_fd;
        other.socket_fd = -1;
    }
    return *this;
}


snet::net::Socket::~Socket() {
    if (socket_fd >= 0) {
        close();
    }
}


auto snet::net::Socket::bind(
    const std::uint16_t port) const
    -> void {
    // Create the address structure for IPv4.
    auto addr = sys::sockaddr_in{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = sys::AF_INET;
    addr.sin_port = sys::htons(port);
    addr.sin_addr = sys::INADDR_ANY;

    if (sys::bind(socket_fd, reinterpret_cast<sys::sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to bind socket to port " + std::to_string(port));
    }
}


auto snet::net::Socket::close() -> void {
    if (socket_fd >= 0) {
        if (sys::close(socket_fd) < 0) {
            throw std::system_error(errno, std::system_category(), "Failed to close socket");
        }
        socket_fd = -1;
    }
}



template <typename S>
    requires std::derived_from<S, snet::net::Socket>
auto snet::net::socket_pair() -> std::pair<S, S> {
    int sv[2];
    if (sys::socketpair(sys::AF_UNIX, sys::SOCK_STREAM, 0, sv) == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to create socket pair");
    }
    return {S(sv[0]), S(sv[1])};
}
