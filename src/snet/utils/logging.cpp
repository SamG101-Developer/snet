export module snet.utils.logging;
import spdlog;
import std;


export namespace snet::utils {
    auto create_logger(std::string const &name) -> std::shared_ptr<spdlog::logger> {
        auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto postfix_name = std::to_string(reinterpret_cast<std::ptrdiff_t>(&name));
        auto logger = std::make_shared<spdlog::logger>(name + "-" + postfix_name, sink);
        logger->set_level(spdlog::level::level_enum::debug);
        spdlog::register_logger(logger);
        return logger;
    }
}
