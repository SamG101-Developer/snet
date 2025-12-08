import openssl;
import spdlog;
import std;

import snet.boot;
import snet.manager.cmd_handler;


auto main(const int argc, char **argv) -> int {
    snet::boot::boot_serex();
    spdlog::set_level(spdlog::level::level_enum::info);

    openssl::SSL_load_error_strings();
    openssl::SSL_library_init();
    openssl::OpenSSL_add_all_algorithms();
    openssl::CRYPTO_secure_malloc_init(std::pow(2, 24), std::pow(2, 6));

    const auto username = std::string("snetwork.directory-service.") + std::to_string(0);
    snet::managers::cmd::handle_directory(username);

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    openssl::CRYPTO_secure_malloc_done();

    return 0;
}
