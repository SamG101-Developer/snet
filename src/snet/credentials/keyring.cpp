module;
#include <libsecret/secret.h>

export module snet.credentials.keyring;
import spdlog;
import std;

using namespace std::literals::string_literals;


static constexpr SecretSchema MY_SCHEMA = {
    "com.snet.credentials", SECRET_SCHEMA_NONE,
    {
        {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {"username", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}
    }
};


export namespace snet::credentials::keyring {
    auto set_password(
        const std::string_view user,
        const std::string_view info)
        -> bool {
        GError *error = nullptr;
        // Store the password in the keyring.
        const auto ok = secret_password_store_sync(
            &MY_SCHEMA,
            SECRET_COLLECTION_DEFAULT,
            ("Private key for "s + user).c_str(),
            info.data(),
            nullptr,
            &error,
            "service", "snet-credentials",
            "username", user.data(),
            nullptr
        );

        // Check for errors.
        if (not ok) {
            spdlog::warn(std::format("Failed to store password in keyring: {}", error->message));
            g_error_free(error);
            return false;
        }
        return true;
    }

    auto get_password(
        const std::string_view user)
        -> std::string {
        // Retrieve the password from the keyring.
        GError *error = nullptr;
        const auto info = secret_password_lookup_sync(
            &MY_SCHEMA,
            nullptr,
            &error,
            "service", "snet-credentials",
            "username", user.data(),
            nullptr
        );

        // Check for errors.
        if (info == nullptr) {
            spdlog::warn(std::format("Failed to lookup password in keyring: {}", error->message));
            g_error_free(error);
            return "";
        }

        auto result = std::string{info};
        secret_password_free(info);
        return result;
    }

    auto del_password(
        const std::string_view user)
        -> bool {
        // Delete the password from the keyring.
        GError *error = nullptr;
        const auto ok = secret_password_clear_sync(
            &MY_SCHEMA,
            nullptr,
            &error,
            "service", "snet-credentials",
            "username", user.data(),
            nullptr
        );

        // Check for errors.
        if (not ok) {
            spdlog::warn(std::format("Failed to delete password from keyring: {}", error->message));
            g_error_free(error);
            return false;
        }
        return true;
    }
}
