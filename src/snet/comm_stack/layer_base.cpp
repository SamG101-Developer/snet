export module snet.comm_stack.layer_base;
import spdlog;
import std;

import snet.comm_stack.request;


export namespace snet::comm_stack::layers {
    class LayerBase {
    protected:
        std::shared_ptr<spdlog::logger> m_logger;

    public:
        explicit LayerBase(std::shared_ptr<spdlog::logger> logger);
        virtual ~LayerBase() = default;

        virtual auto layer_proto_name()
            -> std::string = 0;

        virtual auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req = nullptr)
            -> void = 0;
    };
}


snet::comm_stack::layers::LayerBase::LayerBase(
    std::shared_ptr<spdlog::logger> logger) :
    m_logger(std::move(logger)) {
}
