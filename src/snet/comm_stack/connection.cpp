module;

export module snet.comm_stack.connection;
import std;
import openssl;
import snet.crypt.bytes;


export namespace snet::comm_stack {
    enum class ConnectionState {
        NOT_CONNECTED = 0,
        PENDING_CONNECTION = 1,
        CONNECTION_OPEN = 2,
        CONNECTION_CLOSED = 3
    };

    struct Connection {
        std::string peer_ip;
        std::uint16_t peer_port;
        crypt::bytes::RawBytes peer_id;
        crypt::bytes::RawBytes conn_tok;
        ConnectionState state = ConnectionState::NOT_CONNECTED;
        openssl::EVP_PKEY *peer_epk;
        openssl::EVP_PKEY *self_esk;
        openssl::X509 *peer_cert;
        std::optional<crypt::bytes::SecureBytes> e2e_key;

        [[nodiscard]]
        [[gnu::always_inline]]
        inline auto is_accepted() const -> bool;

        [[nodiscard]]
        [[gnu::always_inline]]
        inline auto is_rejected() const -> bool;

        [[gnu::always_inline]]
        inline auto clean_ephemeral_keys() -> void;
    };

    struct ConnectionCache {
        inline static std::map<crypt::bytes::RawBytes, std::unique_ptr<Connection>> connections = {};

        inline static std::vector<std::tuple<std::string, std::uint16_t, crypt::bytes::RawBytes>> cached_nodes = {};
    };
}


auto snet::comm_stack::Connection::is_accepted() const -> bool {
    return state == ConnectionState::CONNECTION_OPEN;
}


auto snet::comm_stack::Connection::is_rejected() const -> bool {
    return state == ConnectionState::CONNECTION_CLOSED;
}


auto snet::comm_stack::Connection::clean_ephemeral_keys() -> void {
    openssl::EVP_PKEY_free(self_esk);
    self_esk = nullptr;
}
