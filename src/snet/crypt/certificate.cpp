export module snet.crypt.certificate;
import openssl;
import std;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.hash;
import snet.utils.encoding;


export namespace snet::crypt::certificate {
    auto create_self_signed_certificate(openssl::EVP_PKEY *sk) -> openssl::X509* {
        // Create an X509 certificate object.
        const auto cert = openssl::X509_new();

        // Set the version of the certificate, serial number, time limit and public key.
        openssl::X509_set_version(cert, 2);
        openssl::ASN1_INTEGER_set(openssl::X509_get_serialNumber(cert), 1);
        openssl::X509_gmtime_adj(openssl::X509_getm_notBefore(cert), 0);
        openssl::X509_gmtime_adj(openssl::X509_getm_notAfter(cert), 31536000L);
        openssl::X509_set_pubkey(cert, sk);

        // Create the identifier by hashing the public key bytes.
        const auto pk_bytes = asymmetric::serialize_public(sk);
        auto id = hash::sha3_256(pk_bytes);
        const auto hex_id = utils::to_hex(id);

        // Create a new X.509 name and set the subject and issuer names.
        const auto name = openssl::X509_get_issuer_name(cert);
        openssl::X509_NAME_add_entry_by_txt(name, "O", openssl::MBSTRING_ASC, reinterpret_cast<const unsigned char*>("SNetwork"), -1, -1, 0);
        openssl::X509_NAME_add_entry_by_txt(name, "CN", openssl::MBSTRING_ASC, reinterpret_cast<const unsigned char*>(hex_id.data()), static_cast<int>(hex_id.size()), -1, 0);

        // Set the name and sign the certificate with the private key.
        openssl::X509_set_subject_name(cert, name);
        openssl::X509_sign(cert, sk, nullptr);
        return cert;
    }

    auto verify_certificate(openssl::X509 *cert, openssl::EVP_PKEY *pk) -> bool {
        // Verify the certificate using the public key.
        return openssl::X509_verify(cert, pk) == 1;
    }

    auto serialize_certificate(openssl::X509 const *cert) -> bytes::RawBytes {
        // Serialize the X509 certificate to DER format.
        const auto len = openssl::i2d_X509(cert, nullptr);
        auto buf = std::vector<std::uint8_t>(len);
        auto p = buf.data();
        openssl::i2d_X509(cert, &p);
        return buf;
    }

    auto load_certificate(
        bytes::RawBytes const &cert_bytes)
        -> openssl::X509* {
        // Load the X509 certificate from DER format.
        const auto p = cert_bytes.data();
        const auto cert = openssl::d2i_X509(nullptr, const_cast<const unsigned char**>(&p), static_cast<long>(cert_bytes.size()));
        return cert;
    }

    auto extract_id_from_cert(
        openssl::X509 const *cert)
        -> bytes::RawBytes {
        // Extract the identifier from the certificate's subject common name.
        const auto name = openssl::X509_get_subject_name(cert);
        const auto idx = openssl::X509_NAME_get_index_by_NID(name, 13, -1);
        const auto entry = openssl::X509_NAME_get_entry(name, idx);
        const auto hex_data = openssl::X509_NAME_ENTRY_get_data(entry);
        const auto hex_len = openssl::ASN1_STRING_length(hex_data);
        const auto hex_ptr = openssl::ASN1_STRING_get0_data(hex_data);
        const auto hex_str = std::string(reinterpret_cast<const char*>(hex_ptr), hex_len);
        return utils::from_hex(hex_str);
    }

    auto extract_pkey_from_cert(
        openssl::X509 *cert)
        -> openssl::EVP_PKEY* {
        // Extract the public key from the certificate.
        const auto pk = openssl::X509_get_pubkey(cert);
        return pk;
    }
}
