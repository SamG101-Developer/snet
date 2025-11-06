export module snet.constants;
import spdlog;
import std;

import snet.utils.files;


export namespace snet::constants {
    /**
     * Generate the directory path used for caching. This is platform-dependent, and falls back to the current working
     * directory if no support is available for cache paths form environment variables.
     * @return The filesystem path to use for caching.
     */
    auto get_cache_dir() -> std::filesystem::path;

    /**
     * Create a file and fill it with a default json object if it does not already exist. This allows for creating a
     * file with default content but not overwriting existing data.
     * @param path The path to the file to create.
     */
    auto create_if_not_exists(const std::filesystem::path &path) -> void;

    /**
     * The generated cache directory path, used as the base for other cache paths and files. This is initialized at
     * runtime, once.
     */
    const auto CACHE_DIR = get_cache_dir();

    /**
     * The file containing profiles logged in to this system. For each profile in this file, there is keyring data
     * stored to allow for password matching. Keys/certs stored too.
     */
    const auto PROFILE_FILE = CACHE_DIR / "profiles" / "profiles.json";

    /**
     * This directory contains a cache file per profile, which stores data such as known nodes, directory service
     * information, etc. For each profile in profile.json, there is a matching
     * @code profiles/profile-cache/{profile_id}.json@endcode file.
     */
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
    if (not std::filesystem::exists(path / "profiles" / "directory-service.json")) {
        utils::write_file(path / "profiles" / "directory-service.json", "{}");
    }
    std::filesystem::create_directories(path / "profiles" / "profile-cache");
    std::filesystem::create_directories(path / "profiles" / "directory-service-servers");
    std::filesystem::create_directories(path / "profiles" / "directory-service-node-cache");
    std::filesystem::create_directories(path / "keyring");
    return path;
}
