module;
#include <CLI/CLI.hpp>

export module snet.cli;
import snet.manager.cmd_handler;


export namespace snet::cli {
    auto create_cli(int argc, char **argv) -> int;
}


auto snet::cli::create_cli(const int argc, char **argv) -> int {
    CLI::App app{"A distributed anonymous overlay network"};

    // Subcommands
    const auto profiles = app.add_subcommand("profiles", "Manage profiles using the network");
    const auto join = app.add_subcommand("join", "Join the network");
    const auto directory = app.add_subcommand("directory", "Join the network as a directory node");
    const auto exit_net = app.add_subcommand("exit", "Exit the network");
    const auto clear = app.add_subcommand("clear", "Clear the terminal");

    // Profiles subcommands
    std::string username;
    std::string password;

    const auto create_profile = profiles->add_subcommand("create", "Create a new profile");
    create_profile->add_option("--name", username, "Name of profile")->required();
    create_profile->add_option("--pass", password, "Password of profile");

    const auto list_profiles = profiles->add_subcommand("list", "List all profiles");

    const auto delete_profile = profiles->add_subcommand("delete", "Delete a profile");
    delete_profile->add_option("--name", username, "Name of profile")->required();
    delete_profile->add_option("--pass", password, "Password of profile");

    // Join command options
    join->add_option("--name", username, "Name of profile")->required();
    join->add_option("--pass", password, "Password of profile");

    // Directory command options
    directory->add_option("--name", username, "Name of directory node")->required();

    CLI11_PARSE(app, argc, argv);

    if (create_profile->parsed()) {
        std::cout << "Creating profile: " << username << "\n";
    }
    else if (list_profiles->parsed()) {
        std::cout << "Listing profiles\n";
    }
    else if (delete_profile->parsed()) {
        std::cout << "Deleting profile: " << username << "\n";
    }
    else if (join->parsed()) {
        std::cout << "Joining network with profile: " << username << "\n";
    }
    else if (directory->parsed()) {
        std::cout << "Joining as directory node: " << username << "\n";
    }
    else if (exit_net->parsed()) {
        std::cout << "Exiting network\n";
    }
    else if (clear->parsed()) {
        std::cout << "Clearing terminal\n";
    }

    return 0;
}
