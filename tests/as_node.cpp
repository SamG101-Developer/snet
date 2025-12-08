import openssl;
import spdlog;
import std;

import snet.boot;
import snet.manager.cmd_handler;

import snet.comm_stack.application_layers.http.layer_http;


auto main(const int argc, char **argv) -> int {
    snet::boot::boot_serex();
    spdlog::set_level(spdlog::level::level_enum::info);

    openssl::SSL_load_error_strings();
    openssl::SSL_library_init();
    openssl::OpenSSL_add_all_algorithms();
    openssl::CRYPTO_secure_malloc_init(std::pow(2, 24), std::pow(2, 6));

    const auto username = std::string("node.") + std::to_string(4);
    const auto password = std::string("pass.") + std::to_string(4);
    snet::managers::cmd::handle_join(username, password);

    // auto http = std::make_unique<snet::comm_stack::layers::http::LayerHttp>(true);
    //
    // while (true) {
    //     std::this_thread::sleep_for(std::chrono::seconds(1));
    // }

    openssl::CRYPTO_secure_malloc_done();

    return 0;
}
