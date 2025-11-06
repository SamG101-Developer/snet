export module snet.utils.encoding;
import snet.crypt.bytes;
import std;


export namespace snet::utils {
    inline auto hex_value(const char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("Invalid hex digit");
    }

    inline auto to_hex(
        const std::span<std::uint8_t> data) ->
        std::string {
        // Convert each byte to its hexadecimal representation.
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::vector<std::uint8_t> hex_data(data.size() * 2);
        for (std::size_t i = 0; i < data.size(); ++i) {
            hex_data[i * 2] = hex_chars[data[i] >> 4 & 0x0F];
            hex_data[i * 2 + 1] = hex_chars[data[i] & 0x0F];
        }
        return {hex_data.begin(), hex_data.end()};
    }

    template <bool Secure = false>
    inline auto from_hex(
        std::string const &hex_str) ->
        std::conditional_t<Secure, crypt::bytes::SecureBytes, crypt::bytes::RawBytes> {
        // Convert the hexadecimal string back to bytes.
        if (hex_str.size() % 2 != 0) {
            throw std::invalid_argument("Invalid hex string length");
        }
        auto data = std::conditional_t<Secure, crypt::bytes::SecureBytes, crypt::bytes::RawBytes>(hex_str.size() / 2);
        for (auto i = 0uz; i < data.size(); ++i) {
            const auto hi = hex_value(hex_str[2 * i]);
            const auto lo = hex_value(hex_str[2 * i + 1]);
            data[i] = (hi << 4) | lo;
        }
        return data;
    }

    template <bool Secure = false>
    auto encode_string(
        const std::string &str) ->
        std::conditional_t<Secure, crypt::bytes::SecureBytes, crypt::bytes::RawBytes> {
        // Encode the string to bytes using UTF-8 encoding.
        return {str.begin(), str.end()};
    }

    template <bool Secure = false>
    auto encode_string(
        const std::string_view str) ->
        std::conditional_t<Secure, crypt::bytes::SecureBytes, crypt::bytes::RawBytes> {
        // Encode the string to bytes using UTF-8 encoding.
        return {str.begin(), str.end()};
    }

    inline auto decode_bytes(
        const std::span<const std::uint8_t> data) ->
        std::string {
        // Decode the bytes to a string using UTF-8 encoding.
        return {data.begin(), data.end()};
    }

    inline auto crc32(
        const std::span<const std::uint8_t> data) ->
        std::uint32_t {
        // Compute the CRC32 checksum of the data.
        auto crc = 0xFFFFFFFF;
        for (const auto byte : data) {
            crc ^= byte;
            for (auto j = 0; j < 8; ++j) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                }
                else {
                    crc >>= 1;
                }
            }
        }
        return ~crc;
    }
}
