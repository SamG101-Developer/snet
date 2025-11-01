module;
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

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

    namespace level {
        using spdlog::level::level_enum;
    }
}
