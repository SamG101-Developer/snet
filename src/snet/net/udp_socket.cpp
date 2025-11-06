module;
#include <cerrno>

export module snet.net.udp_socket;
import std;
import sys;

import snet.crypt.random;
import snet.net.socket;
import snet.net.fragmentation;
import snet.utils.encoding;


export namespace snet::net {
    class UDPSocket : public Socket {
        static constexpr auto MAX_UDP_SIZE = 64000uz; // Maximum safe UDP payload size (64KB)
        static constexpr auto TIMEOUT_MS = 5000uz; // 5 seconds
        static constexpr auto CLEANUP_INTERVAL_MS = 5000uz; // 5 seconds
        static constexpr auto RECEIVE_INTERNAL_MS = 100uz; // 100 milliseconds

        std::jthread m_internal_receiver_thread;
        std::jthread m_internal_cleanup_thread;
        std::map<std::uint32_t, Message> m_messages_in_progress;
        std::vector<std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t>> m_completed_messages;
        std::mutex m_messages_mutex;

    public:
        explicit UDPSocket(sys::socket_t fd = -1);
        auto send(std::span<std::uint8_t> data, std::string const &ip, std::uint16_t port) const -> void;
        [[nodiscard]] auto recv() -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t>;

    private:
        [[noreturn]] auto internal_recv() -> void;
        auto internal_reassemble_message(std::uint32_t msg_id, std::string &&ip_addr, std::uint16_t port) -> void;
        [[noreturn]] auto internal_cleanup() -> void;
    };
}


snet::net::UDPSocket::UDPSocket(
    const sys::socket_t fd) :
    Socket(sys::AF_INET, sys::SOCK_DGRAM, sys::IPPROTO_UDP, fd) {
    m_internal_receiver_thread = std::jthread([this] { internal_recv(); });
    // m_internal_cleanup_thread = std::jthread([this] { internal_cleanup(); });
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

    // Split the data into fragments if necessary (minimum 1 fragment).
    const auto total_length = data.size();
    const auto max_fragment_data_size = MAX_UDP_SIZE - sizeof(FragHeader);
    const auto fragment_count = static_cast<std::uint16_t>((total_length + max_fragment_data_size - 1) / max_fragment_data_size);

    const auto total_checksum = utils::crc32(data);
    const auto msg_id = crypt::random::random_integer<std::uint32_t>();

    for (std::uint16_t frag_index = 0; frag_index < fragment_count; ++frag_index) {
        const auto offset = frag_index * max_fragment_data_size;
        const auto length = std::min<std::size_t>(max_fragment_data_size, total_length - offset);

        // Create the fragmentation header.
        auto frag_header = FragHeader{
            .msg_id = msg_id,
            .frag_offset = static_cast<std::uint16_t>(offset),
            .frag_count = fragment_count,
            .frag_length = static_cast<std::uint16_t>(length),
            .total_length = static_cast<std::uint64_t>(total_length),
            .total_checksum = total_checksum
        };

        // Create the fragment buffer (header + data).
        auto fragment_buffer = std::vector<std::uint8_t>(sizeof(FragHeader) + length);
        std::memcpy(fragment_buffer.data(), &frag_header, sizeof(FragHeader));
        std::memcpy(fragment_buffer.data() + sizeof(FragHeader), data.data() + offset, length);

        // Send the fragment.
        const auto sent = sys::sendto(
            socket_fd, fragment_buffer.data(), fragment_buffer.size(), 0,
            reinterpret_cast<sys::sockaddr*>(&addr), sizeof(addr));

        if (sent < 0 or sent != static_cast<sys::ssize_t>(fragment_buffer.size())) {
            throw std::system_error(errno, std::system_category(), "Failed to send fragment to " + ip + ":" + std::to_string(port));
        }
    }
}


auto snet::net::UDPSocket::recv()
    -> std::tuple<std::vector<std::uint8_t>, std::string, std::uint16_t> {
    // Wait for the next completed message.
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(RECEIVE_INTERNAL_MS));

        // Lock the messages map for thread safety.
        std::scoped_lock lock(m_messages_mutex);
        if (not m_completed_messages.empty()) {
            auto message_and_metadata = std::move(m_completed_messages.front());
            m_completed_messages.erase(m_completed_messages.begin());
            return message_and_metadata;
        }
    }
}


auto snet::net::UDPSocket::internal_recv()
    -> void {
    while (true) {
        // Prepare sockaddr for sender info
        sys::sockaddr_in src_addr{};
        sys::socklen_t addr_len = sizeof(src_addr);

        // Create a buffer to hold the received data.
        auto temp_buffer = std::vector<std::uint8_t>(MAX_UDP_SIZE);
        const auto recv_len = sys::recvfrom(
            socket_fd, temp_buffer.data(), temp_buffer.size(), 0,
            reinterpret_cast<sys::sockaddr*>(&src_addr), &addr_len);

        // Handle errors and incomplete data.
        if (recv_len <= 0) {
            throw std::system_error(errno, std::system_category(), "Failed to receive data");
        }

        if (static_cast<std::size_t>(recv_len) < sizeof(FragHeader)) {
            throw std::runtime_error("Received data is smaller than fragmentation header size");
        }

        // Split the temp_buffer into the fragmentation header, and data.
        auto frag_header = FragHeader{};
        auto frag_data = std::vector<std::uint8_t>(static_cast<std::size_t>(recv_len) - sizeof(FragHeader));
        std::memcpy(&frag_header, temp_buffer.data(), sizeof(FragHeader));
        std::memcpy(frag_data.data(), temp_buffer.data() + sizeof(FragHeader), frag_data.size());

        // Check the fragment length matches the received data length.
        if (frag_header.frag_length != frag_data.size()) {
            throw std::runtime_error("Fragment length mismatch with received data size");
        }

        // Lock the messages map for thread safety.
        std::scoped_lock lock(m_messages_mutex);

        // Check if this message ID already exists.
        auto stored_message = static_cast<Message*>(nullptr);
        if (m_messages_in_progress.contains(frag_header.msg_id)) {
            stored_message = &m_messages_in_progress[frag_header.msg_id];
            stored_message->fragments.emplace_back(frag_header, std::move(frag_data));
        }
        else {
            m_messages_in_progress[frag_header.msg_id] = Message{
                .fragments = {Fragment{frag_header, std::move(frag_data)}},
                .first_received = std::chrono::steady_clock::now()
            };
            stored_message = &m_messages_in_progress[frag_header.msg_id];
        }

        // Check if all fragments have been received.
        if (stored_message->fragments.size() == frag_header.frag_count) {
            internal_reassemble_message(
                frag_header.msg_id,
                sys::inet_ntoa(src_addr.sin_addr),
                sys::ntohs(src_addr.sin_port));
        }
    }
}


auto snet::net::UDPSocket::internal_reassemble_message(
    const std::uint32_t msg_id,
    std::string &&ip_addr,
    std::uint16_t port)
    -> void {
    auto const &message = m_messages_in_progress[msg_id];

    // Validate that all "total_size"s and "checksum"s are the same across fragments.
    const auto expected_total_length = message.fragments.front().header.total_length;
    const auto expected_total_checksum = message.fragments.front().header.total_checksum;

    for (auto const &frag : message.fragments) {
        if (frag.header.total_length != expected_total_length) {
            throw std::runtime_error("Fragment total length mismatch during reassembly");
        }
        if (frag.header.total_checksum != expected_total_checksum) {
            throw std::runtime_error("Fragment total checksum mismatch during reassembly");
        }
    }

    // Create the output buffer with the total length.
    auto final_buffer = std::vector<std::uint8_t>(expected_total_length);
    for (auto const &frag : message.fragments) {
        const auto offset = frag.header.frag_offset;
        const auto length = frag.header.frag_length;

        if (offset + length > expected_total_length) {
            throw std::runtime_error("Fragment exceeds total message length during reassembly");
        }

        std::memcpy(final_buffer.data() + offset, frag.data.data(), length);
    }

    // Verify the checksum of the reassembled message.
    const auto computed_checksum = utils::crc32(final_buffer);
    if (computed_checksum != expected_total_checksum) {
        throw std::runtime_error("Reassembled message checksum mismatch");
    }

    // Store the completed message.
    m_completed_messages.emplace_back(std::move(final_buffer), std::move(ip_addr), port);
    m_messages_in_progress.erase(msg_id);
}


auto snet::net::UDPSocket::internal_cleanup()
    -> void {
    while (true) {
        // Pause to avoid busy-waiting.
        std::this_thread::sleep_for(std::chrono::milliseconds(CLEANUP_INTERVAL_MS));

        // Grab the current time and lock the messages map.
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(m_messages_mutex);

        for (auto it = m_messages_in_progress.begin(); it != m_messages_in_progress.end();) {
            const auto &message = it->second;
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - message.first_received);

            // Timed out => erase the message.
            if (duration.count() >= TIMEOUT_MS / 1000) {
                it = m_messages_in_progress.erase(it);
            }

            // Not timed out => continue to next message.
            else {
                ++it;
            }
        }
    }
}
