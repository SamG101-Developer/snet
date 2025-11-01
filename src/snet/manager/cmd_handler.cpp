export module snet.manager.cmd_handler;
import spdlog;
import std;

import snet.manager.ds_manager;
import snet.manager.profile_manager;
import snet.nodes.directory_node;
import snet.nodes.node;
import snet.utils.encoding;


namespace snet::managers::cmd {
    auto handle_profile(
        std::vector<std::string> const &args)
        -> void;

    auto handle_clear(
        std::vector<std::string> const &args)
        -> void;

    auto handle_directory(
        std::vector<std::string> const &args)
        -> void;

    auto handle_join(
        std::vector<std::string> const &args)
        -> void;
}


auto snet::managers::cmd::handle_profile(
    std::vector<std::string> const &args)
    -> void {
    const auto &subcommand = args[1];
    if (subcommand == "create") {
        profile::create_profile(args[2], args[3]);
    }
    else if (subcommand == "delete") {
        profile::delete_profile(args[2], args[3]);
    }
    else if (subcommand == "list") {
        const auto usernames = profile::list_usernames();
        for (const auto &username : usernames) { spdlog::info(username); }
    }
}


auto snet::managers::cmd::handle_clear(
    std::vector<std::string> const &args)
    -> void {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}


auto snet::managers::cmd::handle_directory(
    std::vector<std::string> const &args)
    -> void {
    const auto wrapped_info = ds::validate_directory_profile(args[1]);
    if (not wrapped_info.has_value()) {
        spdlog::error("Invalid directory profile credentials.");
        return;
    }
    const auto &info = *wrapped_info;
    auto directory_node = nodes::DirectoryNode(utils::encode_string(args[1]), std::get<0>(info), std::get<2>(info), std::get<4>(info));
    while (true) {}
}


auto snet::managers::cmd::handle_join(
    std::vector<std::string> const &args)
    -> void {
    const auto wrapped_info = profile::validate_profile(args[1], args[2]);
    if (not wrapped_info.has_value()) {
        spdlog::error("Invalid profile credentials.");
        return;
    }
    const auto &info = *wrapped_info;
    auto node = nodes::Node(std::get<0>(info), std::get<2>(info));
    while (true) {}
}
