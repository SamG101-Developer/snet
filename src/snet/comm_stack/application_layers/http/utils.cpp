module;
#include <genex/to_container.hpp>
#include <genex/algorithms/contains.hpp>
#include <genex/views/drop.hpp>
#include <genex/views/filter.hpp>
#include <genex/views/split.hpp>
#include <genex/views/transform.hpp>

export module snet.comm_stack.application_layers.http.utils;
import std;
import sys;

import snet.net.socket;
import snet.crypt.bytes;


export namespace snet::comm_stack::layers::http {
    class SelectableBytesIO {
        net::TCPSocket m_notif_socket;
        net::TCPSocket m_write_socket;

    public:
        SelectableBytesIO() {
            std::tie(m_notif_socket, m_write_socket) = net::socket_pair<net::TCPSocket>();
        }

        [[nodiscard]]
        auto fileno() const -> sys::socket_t {
            return m_notif_socket.fileno();
        }

        auto write(const std::span<std::uint8_t> data) const -> void {
            m_write_socket.send(data);
        }

        [[nodiscard]]
        auto recv() const -> std::vector<std::uint8_t> {
            return m_notif_socket.recv();
        }

        auto close() -> void {
            m_notif_socket.close();
            m_write_socket.close();
        }
    };

    class HttpParser {
        crypt::bytes::RawBytes m_http;

    public:
        explicit HttpParser(
            crypt::bytes::RawBytes http) :
            m_http(std::move(http)) {
        }

        auto method() -> crypt::bytes::RawBytes {
            auto parts = m_http | genex::views::split(' ') | genex::to<std::vector>();
            return parts[0];
        }

        auto response_code() -> std::uint32_t {
            auto parts = m_http | genex::views::split(' ') | genex::to<std::vector>();
            return std::stoul(std::string(parts[1].begin(), parts[1].end()));
        }

        auto headers() -> std::map<std::string, std::string> {
            auto hs_vec = m_http
                | genex::views::split('\n')
                | genex::views::drop(1)
                | genex::views::filter([](auto const &line) { return genex::algorithms::contains(line, ':'); })
                | genex::views::transform([](auto const &line) {
                    auto sub_parts = line | genex::views::split(':') | genex::to<std::vector>();
                    auto pair = std::make_pair(sub_parts[0] | genex::to<std::string>(), sub_parts[1] | genex::to<std::string>());
                    std::get<1>(pair) = std::get<1>(pair).substr(1); // Remove leading space
                    return pair;
                })
                | genex::to<std::vector>();
            return {hs_vec.begin(), hs_vec.end()};
        }
    };
}
