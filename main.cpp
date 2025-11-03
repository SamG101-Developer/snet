import openssl;
import spdlog;
import std;

import snet.comm_stack.request;
import snet.credentials.keyring;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.symmetric;
import snet.crypt.hash;
import snet.crypt.random;
import snet.net.socket;
import snet.utils.assert;
import snet.utils.encoding;

import snet.manager.cmd_handler;
import snet.manager.profile_manager;
import snet.manager.ds_manager;

import snet.boot;
import snet.cli;


// auto test_signature_functions() -> void {
//     // Define a fixed session token for the test.
//     constexpr auto session_token_len = 32;
//     const auto session_token = snet::crypt::random::random_bytes(session_token_len);
//
//     // Node A's static secret and public key pair.
//     const auto sSKa = snet::crypt::asymmetric::generate_sig_keypair();
//     const auto PKI_sPKa = snet::crypt::asymmetric::serialize_public(sSKa);
//
//     // Node B's static secret and public key pair, to get its identifier.
//     const auto sSKb = snet::crypt::asymmetric::generate_sig_keypair();
//     const auto sPKb = snet::crypt::asymmetric::serialize_public(sSKb);
//     const auto id_b = snet::crypt::hash::sha3_256(sPKb);
//
//     // Node A signs a message for Node B with authenticated additional data.
//     const auto msg_a = snet::crypt::bytes::SecureBytes{'h', 'e', 'l', 'l', 'o'};
//     const auto aad_a = snet::crypt::asymmetric::create_aad(session_token, id_b);
//     const auto sig_a = snet::crypt::asymmetric::sign(sSKa, msg_a, aad_a.get());
//
//     // Node B verifies the signature from Node A.
//     const auto sPKa_for_b = snet::crypt::asymmetric::load_public_key(PKI_sPKa);
//     const auto exp_aad_b = snet::crypt::asymmetric::create_aad(session_token, id_b);
//     const auto ver_a = snet::crypt::asymmetric::verify(
//         sPKa_for_b, sig_a, msg_a, aad_a.get(), {}, exp_aad_b.get(), 10000);
//
//     snet::utils::assert(ver_a);
//     spdlog::info("Signature verification successful");
// }
//
//
// auto test_kem_functions() -> void {
//     // Node B's ephemeral secret and public key pair.
//     const auto eSKb = snet::crypt::asymmetric::generate_kem_keypair();
//     const auto PKI_ePKb = snet::crypt::asymmetric::serialize_public(eSKb);
//
//     // Node B's ephemeral public key from Node A's perspective.
//     const auto ePKb_for_a = snet::crypt::asymmetric::load_public_key(PKI_ePKb);
//
//     // Node A encapsulates a shared secret and ciphertext using Node B's public key.
//     const auto [ct_a, ss_a] = snet::crypt::asymmetric::encaps(ePKb_for_a);
//
//     // Node B decapsulates the shared secret from the ciphertext using own private key.
//     const auto ct_b = ct_a;
//     const auto ss_b = snet::crypt::asymmetric::decaps(eSKb, ct_b);
//
//     // Check the shared secrets match.
//     snet::utils::assert(ss_a.size() == ss_b.size());
//     snet::utils::assert(not ss_a.empty());
//     snet::utils::assert(openssl::CRYPTO_memcmp(ss_a.data(), ss_b.data(), ss_a.size()) == 0);
//     spdlog::info("KEM shared secret match successful");
// }
//
//
// auto test_symmetric_encryption() -> void {
//     // Generate a key and message
//     const auto key = snet::crypt::symmetric::generate_key();
//     const auto message = snet::crypt::bytes::SecureBytes{'h', 'e', 'l', 'l', 'o'};
//
//     // Encrypt and decrypt the message
//     auto [ciphertext, iv, tag] = snet::crypt::symmetric::encrypt(key, message);
//     std::cout << snet::utils::to_hex(ciphertext) << std::endl;
//     const auto decrypted_message = snet::crypt::symmetric::decrypt(key, ciphertext, iv, tag);
//
//     // Check if the decrypted message matches the original message
//     snet::utils::assert(decrypted_message.size() == message.size());
//     snet::utils::assert(openssl::CRYPTO_memcmp(decrypted_message.data(), message.data(), message.size()) == 0);
//     spdlog::info("Symmetric encryption/decryption successful");
// }
//
//
// auto test_certificate() -> void {
//     // Generate a key and self-signed certificate
//     const auto sk = snet::crypt::asymmetric::generate_sig_keypair();
//     const auto cert = snet::crypt::certificate::create_self_signed_certificate(sk);
//     const auto PKI_pk = snet::crypt::asymmetric::serialize_public(sk);
//
//     // Verify the certificate
//     const auto pk = snet::crypt::asymmetric::load_public_key(PKI_pk);
//     const auto is_valid = snet::crypt::certificate::verify_certificate(cert, pk);
//     snet::utils::assert(is_valid);
//     spdlog::info("Certificate verification successful");
// }
//
//
// auto test_sockets() -> void {
//     // 2 UDP sockets talking to each other
//     std::barrier sync_point(2);
//
//     auto socket_steps_1 = [&sync_point] {
//         spdlog::info("S1 Sending data");
//         auto data = std::vector<std::uint8_t>{'h', 'e', 'l', 'l', 'o'};
//         const auto socket = snet::net::Socket();
//         socket.bind(12345);
//         sync_point.arrive_and_wait();
//
//         socket.send(data, std::string("127.0.0.1"), 12346);
//         auto [recv_data, _, _] = socket.recv();
//         spdlog::info("S1 Received data: " + std::string(recv_data.begin(), recv_data.end()));
//     };
//
//     auto socket_steps_2 = [&sync_point] {
//         spdlog::info("S2 Sending data");
//         auto data = std::vector<std::uint8_t>{'g', 'o', 'o', 'd', 'b', 'y', 'e'};
//         const auto socket = snet::net::Socket();
//         socket.bind(12346);
//         sync_point.arrive_and_wait();
//
//         socket.send(data, std::string("127.0.0.1"), 12345);
//         auto [recv_data, _, _] = socket.recv();
//         spdlog::info("S2 Received data: " + std::string(recv_data.begin(), recv_data.end()));
//     };
//
//     auto socket_thread_1 = std::jthread(socket_steps_1);
//     auto socket_thread_2 = std::jthread(socket_steps_2);
//     spdlog::info("Socket test completed");
// }


auto main(const int argc, char **argv) -> int {
    snet::boot::boot_serex();
    spdlog::set_level(spdlog::level::level_enum::info);

    openssl::SSL_load_error_strings();
    openssl::SSL_library_init();
    openssl::OpenSSL_add_all_algorithms();
    openssl::CRYPTO_secure_malloc_init(std::pow(2, 24), std::pow(2, 6));

    // test_kem_functions();
    // test_symmetric_encryption();
    // test_certificate();
    // test_sockets();
    // test_signature_functions();

    auto ret = 0;
    ret = snet::cli::create_cli(argc, argv);

    // const auto name = std::string("snetwork.directory-service.") + std::to_string(0);
    // snet::managers::ds::create_directory_profile(name);
    // snet::managers::cmd::handle_directory(name);

    // constexpr auto i = 0;
    // const auto username = std::string("node.") + std::to_string(i);
    // const auto password = std::string("pass.") + std::to_string(i);
    // snet::managers::profile::delete_profile(username, password);
    // snet::managers::profile::create_profile(username, password);
    // snet::managers::cmd::handle_join(username, password);

    // auto join_as_directory_node = [] {
    //     const auto username = std::string("snetwork.directory-service.") + std::to_string(0);
    //     snet::managers::cmd::handle_directory(username);
    // };
    //
    // auto join_as_node = [] {
    //     const auto username = std::string("node.") + std::to_string(0);
    //     const auto password = std::string("pass.") + std::to_string(0);
    //     snet::managers::cmd::handle_join(username, password);
    // };

    // Join each as threads
    // auto dir_thread = std::jthread(join_as_directory_node);
    // std::this_thread::sleep_for(std::chrono::seconds(1));
    // auto node_thread = std::jthread(join_as_node);
    //
    // while (true) {
    //     std::this_thread::sleep_for(std::chrono::seconds(1));
    // }

    openssl::CRYPTO_secure_malloc_done();

    return ret;
}
