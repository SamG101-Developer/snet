export module snet.utils.encoding;
import snet.crypt.bytes;
import std;


export namespace snet::utils {
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
        for (std::size_t i = 0; i < data.size(); ++i) {
            const auto high_nibble = static_cast<std::uint8_t>(std::stoi(hex_str.substr(i * 2, 1), nullptr, 16));
            const auto low_nibble = static_cast<std::uint8_t>(std::stoi(hex_str.substr(i * 2 + 1, 1), nullptr, 16));
            data[i] = (high_nibble << 4) | low_nibble;
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

    inline auto decode_bytes(
        const std::span<const std::uint8_t> data) ->
        std::string {
        // Decode the bytes to a string using UTF-8 encoding.
        return {data.begin(), data.end()};
    }
}
