export module snet.constants;
import spdlog;
import std;

import snet.utils.files;


export namespace snet::constants {
    auto get_cache_dir() -> std::filesystem::path;
    auto create_if_not_exists(const std::filesystem::path &path) -> void;

    const auto CACHE_DIR = get_cache_dir();
    const auto PROFILE_FILE = CACHE_DIR / "profiles" / "profiles.json";
    const auto PROFILE_CACHE_DIR = CACHE_DIR / "profiles" / "profile-cache";

    const auto DIRECTORY_SERVICE_PUBLIC_FILE = CACHE_DIR / "profiles" / "directory-service.json";
    const auto DIRECTORY_SERVICE_PRIVATE_DIR = CACHE_DIR / "profiles" / "directory-service-servers";
    const auto DIRECTORY_SERVICE_NODE_CACHE_DIR = CACHE_DIR / "profiles" / "directory-service-node-cache";

    const auto KEYRING_DIR = CACHE_DIR / "keyring";
}


auto snet::constants::get_cache_dir() -> std::filesystem::path {
    const auto app_name = "snet";
    auto path = std::filesystem::path();
#ifdef _WIN32
    if (const char *localAppData = std::getenv("LOCALAPPDATA"))
        path = std::filesystem::path(localAppData) / app_name / "Cache";
#elif __APPLE__
    if (const char *home = std::getenv("HOME"))
        path = std::filesystem::path(home) / "Library" / "Caches" / app_name;
#else // Linux / Unix
    const char *home = std::getenv("HOME");
    spdlog::info(std::format("Home path: {}", path.string()));
    if (home) {
        spdlog::info(std::format("Created cache directory at {}/.cache/{}", home, app_name));
        path = std::filesystem::path(home) / ".cache" / app_name;
    }
#endif
    // Fallback: current directory
    if (path.empty()) {
        spdlog::warn("No cache directory provided, using current working directory");
        path = std::filesystem::current_path() / app_name / "Cache";
    }

    // Create the path if it doesn't exist
    std::filesystem::create_directories(path);
    std::filesystem::create_directories(path / "profiles");
    if (not std::filesystem::exists(path / "profiles" / "profiles.json")) {
        utils::write_file(path / "profiles" / "profiles.json", "{}");
    }
    std::filesystem::create_directories(path / "profiles" / "profile-cache");
    std::filesystem::create_directories(path / "profiles" / "directory-service-servers");
    std::filesystem::create_directories(path / "profiles" / "directory-service-node-cache");
    std::filesystem::create_directories(path / "keyring");
    return path;
}
