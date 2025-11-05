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
            sys::socket_t fd = 0);

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

    class UDPSocket : public Socket {
    public:
        explicit UDPSocket(sys::socket_t fd = 0);
        auto send(std::span<std::uint8_t> data, std::string const &ip, std::uint16_t port) const -> void;
        [[nodiscard]] auto recv() const -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t>;
    };

    class TCPSocket : public Socket {
    public:
        explicit TCPSocket(sys::socket_t fd = 0);
        auto connect(std::string const &ip, std::uint16_t port) const -> void;
        auto listen(std::int32_t backlog = 5) const -> void;
        [[nodiscard]] auto accept() const -> TCPSocket;
        auto send(std::span<std::uint8_t> data) const -> void;
        [[nodiscard]] auto recv() const -> std::vector<std::uint8_t>;
    };

    template <typename S>
        requires std::derived_from<S, Socket>
    auto socket_pair() -> std::pair<S, S>;

    auto select(
        std::vector<sys::socket_t> const &read_fds,
        std::vector<sys::socket_t> const &write_fds,
        std::vector<sys::socket_t> const &except_fds,
        std::optional<std::chrono::milliseconds> timeout = std::nullopt)
        -> std::tuple<std::vector<sys::socket_t>, std::vector<sys::socket_t>, std::vector<sys::socket_t>>;
}


snet::net::Socket::Socket(
    const std::int32_t family,
    const std::int32_t type,
    const std::int32_t protocol,
    const sys::socket_t fd) :
    socket_fd(fd) {

    socket_fd = sys::socket(family, type, protocol);
    if (socket_fd == static_cast<sys::socket_t>(-1)) {
        throw std::system_error(errno, std::system_category(), "Failed to create socket");
    }

    constexpr auto opt = 1;
    if (sys::setsockopt(socket_fd, sys::SOL_SOCKET, sys::SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to set socket options");
    }
}


snet::net::Socket::Socket(
    Socket &&other) noexcept {
    std::lock_guard lock(other.mtx);
    socket_fd = other.socket_fd;
    other.socket_fd = 0;
}


auto snet::net::Socket::operator=(
    Socket &&other) noexcept
    -> Socket& {
    if (this != &other) {
        std::scoped_lock lock(mtx, other.mtx);
        socket_fd = other.socket_fd;
        other.socket_fd = 0;
    }
    return *this;
}


snet::net::Socket::~Socket() {
    if (socket_fd != 0) {
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
    if (socket_fd != 0) {
        if (sys::close(socket_fd) < 0) {
            throw std::system_error(errno, std::system_category(), "Failed to close socket");
        }
        socket_fd = 0;
    }
}


snet::net::UDPSocket::UDPSocket(
    const sys::socket_t fd) :
    Socket(sys::AF_INET, sys::SOCK_DGRAM, sys::IPPROTO_UDP, fd) {
}


auto snet::net::UDPSocket::send(
    const std::span<std::uint8_t> data,
    std::string const &ip,
    const std::uint16_t port) const -> void {
    // Create the address structure for IPv4.
    auto addr = sys::sockaddr_in{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = sys::AF_INET;
    addr.sin_port = sys::htons(port);
    if (sys::inet_pton(sys::AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        throw std::system_error(errno, std::system_category(), "Invalid IP address: " + ip);
    }

    // Add a frame header specifying the length of the data (size_t, so 8 byte header).
    const auto data_size = data.size();
    auto buffer = std::vector<std::uint8_t>(sizeof(std::size_t) + data_size);
    std::memcpy(buffer.data(), &data_size, sizeof(std::size_t));
    std::memcpy(buffer.data() + sizeof(std::size_t), data.data(), data_size);

    // Send the data.
    const auto sent = sys::sendto(
        socket_fd, buffer.data(), buffer.size(), 0,
        reinterpret_cast<sys::sockaddr*>(&addr), sizeof(addr));

    if (sent < 0 or sent != static_cast<sys::ssize_t>(buffer.size())) {
        throw std::system_error(errno, std::system_category(), "Failed to send data to " + ip + ":" + std::to_string(port));
    }
}


auto snet::net::UDPSocket::recv() const
    -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t> {
    // Prepare sockaddr for sender info
    sys::sockaddr_in src_addr{};
    sys::socklen_t addr_len = sizeof(src_addr);

    // Create a buffer to hold the received data.
    auto header_buffer = std::vector<std::uint8_t>(65535);
    const auto recv_len = sys::recvfrom(
        socket_fd, header_buffer.data(), header_buffer.size(), 0,
        reinterpret_cast<sys::sockaddr*>(&src_addr), &addr_len);

    if (recv_len <= 0) {
        throw std::system_error(errno, std::system_category(), "Failed to receive data");
    }

    if (static_cast<std::size_t>(recv_len) < sizeof(std::size_t)) {
        throw std::runtime_error("Received data is smaller than header size");
    }

    // Extract the data length from the header.
    auto data_size = 0uz;
    std::memcpy(&data_size, header_buffer.data(), sizeof(std::size_t));

    // todo: temp for testing
    if (data_size > 65535 - sizeof(std::size_t)) {
        data_size = 65535 - sizeof(std::size_t);
    }

    else if (data_size + sizeof(std::size_t) != static_cast<std::size_t>(recv_len)) {
        throw std::runtime_error("Received data size does not match header length");
    }

    auto payload = std::vector<std::uint8_t>(data_size);
    std::memcpy(payload.data(), header_buffer.data() + sizeof(std::size_t), data_size);

    // Extract sender IP and port
    char ip_str[sys::INET_ADDRSTRLEN];
    if (sys::inet_ntop(sys::AF_INET, &src_addr.sin_addr, ip_str, sizeof(ip_str)) == nullptr) {
        throw std::system_error(errno, std::system_category(), "Failed to convert sender IP to string");
    }
    const auto sender_ip = std::string(ip_str);
    const auto sender_port = sys::ntohs(src_addr.sin_port);
    return {std::move(payload), sender_ip, sender_port};
}


snet::net::TCPSocket::TCPSocket(
    const sys::socket_t fd) :
    Socket(sys::AF_INET, sys::SOCK_STREAM, sys::IPPROTO_TCP, fd) {
}


auto snet::net::TCPSocket::connect(
    const std::string &ip,
    const std::uint16_t port) const
    -> void {
    // Create the address structure for IPv4.
    auto addr = sys::sockaddr_in{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = sys::AF_INET;
    addr.sin_port = sys::htons(port);
    if (sys::inet_pton(sys::AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        throw std::system_error(errno, std::system_category(), "Invalid IP address: " + ip);
    }

    // Connect to the server.
    if (sys::connect(socket_fd, reinterpret_cast<sys::sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to connect to " + ip + ":" + std::to_string(port));
    }
}


auto snet::net::TCPSocket::listen(
    const std::int32_t backlog) const
    -> void {
    if (sys::listen(socket_fd, backlog) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to listen on socket");
    }
}


auto snet::net::TCPSocket::accept() const
    -> TCPSocket {
    // Accept a new connection.
    const auto client_fd = sys::accept(socket_fd, nullptr, nullptr);
    if (client_fd < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to accept connection");
    }
    return TCPSocket(client_fd);
}


auto snet::net::TCPSocket::send(
    const std::span<std::uint8_t> data) const
    -> void {
    // Add a frame header specifying the length of the data (size_t, so 8 byte header).
    const auto data_size = data.size();
    auto buffer = std::vector<std::uint8_t>(sizeof(std::size_t) + data_size);
    std::memcpy(buffer.data(), &data_size, sizeof(std::size_t));
    std::memcpy(buffer.data() + sizeof(std::size_t), data.data(), data_size);

    // Send the data.
    const auto sent = sys::sendto(
        socket_fd, buffer.data(), buffer.size(), 0,
        nullptr, 0);

    if (sent < 0 or sent != static_cast<sys::ssize_t>(buffer.size())) {
        throw std::system_error(errno, std::system_category(), "Failed to send data");
    }
}


auto snet::net::TCPSocket::recv() const
    -> std::vector<std::uint8_t> {
    // Create a buffer to hold the received data.
    auto header_buffer = std::vector<std::uint8_t>(65535);
    const auto recv_len = sys::recvfrom(
        socket_fd, header_buffer.data(), header_buffer.size(), 0,
        nullptr, nullptr);

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
    return payload;
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


auto snet::net::select(
    std::vector<sys::socket_t> const &read_fds,
    std::vector<sys::socket_t> const &write_fds,
    std::vector<sys::socket_t> const &except_fds,
    const std::optional<std::chrono::milliseconds> timeout)
    -> std::tuple<std::vector<sys::socket_t>, std::vector<sys::socket_t>, std::vector<sys::socket_t>> {
    // Prepare fd_sets (linux compat)
    sys::fd_set read_set;
    sys::fd_set write_set;
    sys::fd_set except_set;

    // Initialize fd_sets and find max fd
    sys::FD_ZERO(&read_set);
    sys::FD_ZERO(&write_set);
    sys::FD_ZERO(&except_set);
    auto max_fd = static_cast<sys::socket_t>(0);

    // Set fds in fd_sets
    for (const auto fd : read_fds) {
        sys::FD_SET(fd, &read_set);
        if (fd > max_fd) max_fd = fd;
    }
    for (const auto fd : write_fds) {
        sys::FD_SET(fd, &write_set);
        if (fd > max_fd) max_fd = fd;
    }
    for (const auto fd : except_fds) {
        sys::FD_SET(fd, &except_set);
        if (fd > max_fd) max_fd = fd;
    }

    // Prepare timeout
    sys::timeval tv{};
    sys::timeval *tv_ptr = nullptr;
    if (timeout.has_value()) {
        tv.tv_sec = static_cast<long>(timeout->count() / 1000);
        tv.tv_usec = static_cast<long>((timeout->count() % 1000) * 1000);
        tv_ptr = &tv;
    }

    // Call select
    if (sys::select(max_fd + 1, &read_set, &write_set, &except_set, tv_ptr) < 0) {
        throw std::system_error(errno, std::system_category(), "Select call failed");
    }

    // Collect ready fds
    auto ready_read_fds = std::vector<sys::socket_t>{};
    auto ready_write_fds = std::vector<sys::socket_t>{};
    auto ready_except_fds = std::vector<sys::socket_t>{};
    for (const auto fd : read_fds) {
        if (sys::FD_ISSET(fd, &read_set)) { ready_read_fds.push_back(fd); }
    }
    for (const auto fd : write_fds) {
        if (sys::FD_ISSET(fd, &write_set)) { ready_write_fds.push_back(fd); }
    }
    for (const auto fd : except_fds) {
        if (sys::FD_ISSET(fd, &except_set)) { ready_except_fds.push_back(fd); }
    }
    return {ready_read_fds, ready_write_fds, ready_except_fds};
}
