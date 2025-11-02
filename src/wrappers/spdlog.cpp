module;
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

export module spdlog;


export namespace spdlog {
    using spdlog::logger;

    using spdlog::trace;
    using spdlog::debug;
    using spdlog::info;
    using spdlog::warn;
    using spdlog::error;
    using spdlog::critical;
    using spdlog::set_level;
    using spdlog::register_logger;
    using spdlog::default_logger;

    namespace level {
        using spdlog::level::level_enum;
    }

    namespace sinks {
        using spdlog::sinks::stdout_color_sink_mt;
    }
}
