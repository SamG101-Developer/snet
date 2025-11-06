export module snet.crypt.random;
import std;
import openssl;
import snet.crypt.bytes;


export namespace snet::crypt::random {
    auto secure_random_bytes(const std::size_t len) -> bytes::SecureBytes {
        // Generate cryptographically secure random bytes of the specified length.
        auto buffer = bytes::SecureBytes(len);
        openssl::RAND_priv_bytes(buffer.data(), static_cast<int>(len));
        return buffer;
    }

    auto random_bytes(const std::size_t len) -> bytes::RawBytes {
        // Generate random bytes of the specified length.
        auto buffer = bytes::RawBytes(len);
        openssl::RAND_bytes(buffer.data(), static_cast<int>(len));
        return buffer;
    }

    template <typename T>
    requires std::integral<T>
    auto random_integer() -> T {
        // Generate a random 32-bit unsigned integer.
        auto value = static_cast<T>(0);
        openssl::RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(T));
        return value;
    }
}
