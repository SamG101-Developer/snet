export module snet.utils.assert;
import std;


export namespace snet::utils {
    struct assertion_error final : std::runtime_error {
        explicit assertion_error(std::string const &message) :
            std::runtime_error("Assertion failed: " + message) {
        }
    };

    auto assert(const bool condition, std::string const &message = "") -> void {
        if (!condition) {
            throw assertion_error(message);
        }
    }
}
