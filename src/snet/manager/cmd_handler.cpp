export module snet.manager.cmd_handler;
import spdlog;
import std;

import snet.manager.ds_manager;
import snet.manager.profile_manager;
import snet.nodes.directory_node;
import snet.nodes.node;
import snet.utils.encoding;


export namespace snet::managers::cmd {
    auto handle_list_profiles()
        -> void;

    auto handle_create_profile(
        std::string const &username,
        std::string const &password)
        -> void;

    auto handle_delete_profile(
        std::string const &username,
        std::string const &password)
        -> void;

    auto handle_directory(
        std::string const &username)
        -> void;

    auto handle_join(
        std::string const &username,
        std::string const &password)
        -> void;

    auto handle_exit()
        -> void;

    auto handle_clear()
        -> void;
}


auto snet::managers::cmd::handle_list_profiles()
    -> void {
    for (const auto &username : profile::list_usernames()) {
        spdlog::info(username);
    }
}


auto snet::managers::cmd::handle_create_profile(
    std::string const &username,
    std::string const &password)
    -> void {
    profile::create_profile(username, password);
}


auto snet::managers::cmd::handle_delete_profile(
    std::string const &username,
    std::string const &password)
    -> void {
    profile::delete_profile(username, password);
}


auto snet::managers::cmd::handle_directory(
    std::string const &username)
    -> void {
    const auto wrapped_info = ds::validate_directory_profile(username);
    if (not wrapped_info.has_value()) {
        spdlog::error("Invalid directory profile credentials.");
        return;
    }

    spdlog::info("Launching directory node");
    const auto &info = *wrapped_info;
    auto directory_node = nodes::DirectoryNode(utils::encode_string(username), std::get<0>(info), std::get<2>(info), std::get<4>(info));
    while (true) {}
}


auto snet::managers::cmd::handle_join(
    std::string const &username,
    std::string const &password)
    -> void {
    const auto wrapped_info = profile::validate_profile(username, password);
    if (not wrapped_info.has_value()) {
        spdlog::error("Invalid profile credentials.");
        return;
    }

    spdlog::info("Lauching node");
    const auto &info = *wrapped_info;
    auto node = nodes::Node(std::get<0>(info), std::get<2>(info));
    while (true) {}
}


auto snet::managers::cmd::handle_exit()
    -> void {
    // Exit the application.
    spdlog::info("Exiting application...");
    std::exit(0);
}


auto snet::managers::cmd::handle_clear()
    -> void {
    // Clear the console screen.
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}
