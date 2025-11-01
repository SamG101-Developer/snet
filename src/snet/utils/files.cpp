export module snet.utils.files;
import std;
import sys;


export namespace snet::utils {
    auto lock_file(const int fd) -> void {
        // Exclusively lock a file at the OS level.
        sys::flock(fd, 2);
    }

    auto unlock_file(const int fd) -> void {
        // Unlock a file at the OS level.
        sys::flock(fd, 8);
    }

    auto read_file(std::filesystem::path const &file_path) -> std::vector<std::uint8_t> {
        // Open the file in binary mode and read its contents into a vector of bytes.
        auto file = std::ifstream(file_path, std::ios::binary);
        auto buffer = std::vector<std::uint8_t>(std::filesystem::file_size(file_path));
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        return buffer;
    }

    auto write_file(
        std::filesystem::path const &file_path,
        const std::span<const std::uint8_t> data) -> void {
        // Open the file in binary mode and write the provided data to it.
        auto file = std::ofstream(file_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    auto write_file(
        std::filesystem::path const &file_path,
        std::string const &data) -> void {
        // Open the file in binary mode and write the provided data to it.
        auto file = std::ofstream(file_path, std::ios::binary);
        file.write(data.data(), data.size());
    }
}
