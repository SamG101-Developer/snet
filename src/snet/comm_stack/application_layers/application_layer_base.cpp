export module snet.comm_stack.application_layers.application_layer_base;
import spdlog;
import std;

import snet.comm_stack.layer_base;
import snet.comm_stack.system_layers.layer_1;
import snet.comm_stack.system_layers.layer_2;
import snet.comm_stack.system_layers.layer_3;
import snet.comm_stack.system_layers.layer_d;
import snet.comm_stack.system_layers.layer_4;


export namespace snet::comm_stack::layers {
    class ApplicationLayerBase : public LayerBase {
    protected:
        Layer1 *m_l1 = nullptr;
        Layer2 *m_l2 = nullptr;
        Layer3 *m_l3 = nullptr;
        LayerD *m_lD = nullptr;
        Layer4 *m_l4 = nullptr;

    public:
        ApplicationLayerBase() : LayerBase(nullptr) {}
        ~ApplicationLayerBase() override = default;

        auto initialize(
            std::shared_ptr<spdlog::logger> logger,
            Layer1 *l1,
            Layer2 *l2,
            Layer3 *l3,
            LayerD *ld,
            Layer4 *l4) -> void;
    };
}


auto snet::comm_stack::layers::ApplicationLayerBase::initialize(
    std::shared_ptr<spdlog::logger> logger,
    Layer1 *l1,
    Layer2 *l2,
    Layer3 *l3,
    LayerD *ld,
    Layer4 *l4)
    -> void {
    m_logger = std::move(logger);
    m_l1 = l1;
    m_l2 = l2;
    m_l3 = l3;
    m_lD = ld;
    m_l4 = l4;
}
