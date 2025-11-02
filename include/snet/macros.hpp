#pragma once

#define MAP_TO_HANDLER(L, ReqType, Condition, Handler, ...) \
    if (auto cast_req = serex::poly_non_owning_cast<ReqType>(req); \
        cast_req != nullptr and Condition) { \
        auto cast_owning_req = serex::poly_owning_cast<ReqType>(std::move(req)); \
        std::jthread( \
            &Layer ## L::Handler, this, peer_ip, peer_port, std::move(cast_owning_req) __VA_OPT__(, __VA_ARGS__)).detach(); \
        return; \
    }


#define MASTER_HANDLER(ReqType, Handler) \
    if (auto cast_res = serex::poly_non_owning_cast<ReqType>(response); \
        cast_res != nullptr) { \
        std::jthread( \
            [this, response=std::move(response), &peer_ip, peer_port] mutable { Handler->handle_command(peer_ip, peer_port, std::move(response)); }).detach(); \
        continue; \
    }
