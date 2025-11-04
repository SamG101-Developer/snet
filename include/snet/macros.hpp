#pragma once

#define MAP_TO_HANDLER(L, ReqType, Condition, Handler, ...) \
    if (auto cast_req = serex::poly_non_owning_cast<ReqType>(req); \
        cast_req != nullptr and Condition) { \
        auto cast_owning_req = serex::poly_owning_cast<ReqType>(std::move(req)); \
        std::jthread( \
            &Layer ## L::Handler, this, peer_ip, peer_port, std::move(cast_owning_req) __VA_OPT__(, __VA_ARGS__)).detach(); \
        return; \
    }


#define MASTER_HANDLER(ReqType, Handler, ...) \
    if (auto cast_res = serex::poly_non_owning_cast<ReqType>(req); \
        cast_res != nullptr) { \
        std::jthread( \
            [this, req=std::move(req), &peer_ip, peer_port __VA_OPT__(, __VA_ARGS__ = std::move(__VA_ARGS__))] mutable {\
                Handler->handle_command(peer_ip, peer_port, std::move(req) __VA_OPT__(, std::move(__VA_ARGS__)));\
            }).detach(); \
        continue; \
    }


#define FORMAT_CONN_INFO(conn) \
    std::format(" {}@{}:{}[{}]", utils::to_hex(conn->peer_id), conn->peer_ip, conn->peer_port, utils::to_hex(conn->conn_tok))

#define FORMAT_REQ_INFO(req) \
    std::format(" {}@{}:{}[{}]", utils::to_hex(req->next_node_id), req->next_node_ip, req->next_node_port, utils::to_hex(req->conn_tok))

#define FORMAT_PEER_INFO() \
    std::format(" ?@{}:{}[{}]", peer_ip, peer_port, utils::to_hex(req->conn_tok))
