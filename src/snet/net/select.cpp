module;
#include <cerrno>

export module snet.net.select;
import std;
import sys;


export namespace snet::net {
    auto select(
        std::vector<sys::socket_t> const &read_fds,
        std::vector<sys::socket_t> const &write_fds,
        std::vector<sys::socket_t> const &except_fds,
        std::optional<std::chrono::milliseconds> timeout = std::nullopt)
        -> std::tuple<std::vector<sys::socket_t>, std::vector<sys::socket_t>, std::vector<sys::socket_t>>;
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
