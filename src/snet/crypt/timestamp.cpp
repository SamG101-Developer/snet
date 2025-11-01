export module snet.crypt.timestamp;
import std;
import snet.crypt.bytes;


export namespace snet::crypt::timestamp {
    constexpr auto TS_BYTES_LEN = sizeof(std::int64_t);
    constexpr auto TS_TOLERANCE_MESSAGE_SIGNATURE = 60;
    constexpr auto TS_TOLERANCE_CERTIFICATE_SIGNATURE = 60 * 60 * 24 * 365;

    auto timestamp()
        -> std::int64_t {
        // Get the current time in milliseconds since the epoch.
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        return now_ms;
    }

    auto timestamp_bytes()
        -> bytes::RawBytes {
        // Pack the current timestamp into bytes.
        const auto ts = timestamp();
        auto buffer = bytes::RawBytes(TS_BYTES_LEN);
        for (std::size_t i = 0; i < TS_BYTES_LEN; ++i) {
            buffer[TS_BYTES_LEN - 1 - i] = static_cast<std::uint8_t>(ts >> (i * 8));
        }
        return buffer;
    }

    auto unpack_timestamp(
        const bytes::ViewBytes &ts_bytes)
        -> std::int64_t {
        // Unpack the timestamp from bytes.
        std::int64_t ts = 0;
        for (std::size_t i = 0; i < TS_BYTES_LEN; ++i) {
            ts |= static_cast<std::int64_t>(ts_bytes[i]) << ((TS_BYTES_LEN - 1 - i) * 8);
        }
        return ts;
    }

    auto timestamp_in_tolerance(
        const std::int64_t timestamp,
        const std::uint32_t tolerance = TS_TOLERANCE_MESSAGE_SIGNATURE)
        -> bool {
        // Get the current time in milliseconds since the epoch.
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

        // Check if the timestamp is within the tolerance.
        return std::abs(now_ms - timestamp) <= tolerance;
    }
}
