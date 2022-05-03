#include "dds.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <tuple>

#include <secp256k1.h>
#include "nlohmann/json.hpp"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include "base64urldecode.h"
#include "random.h"
using dds::CoreInfo;
using dds::DDS;
using dds::Empty;
using dds::Jwt;
using dds::UserConsent;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

struct JWT{
    std::string role;
    std::string user_id;
    int64_t exp;
};

void to_json(nlohmann::json& j, const struct JWT& value) {
    j = nlohmann::json{ {"role", value.role}, {"user_id", value.user_id}, {"exp", value.exp} };
}
void from_json(const nlohmann::json& j, struct JWT& value) {
    j.at("role").get_to(value.role);
    j.at("user_id").get_to(value.user_id);
    j.at("exp").get_to(value.exp);
}
class DDSClient
{
public:
    DDSClient(std::shared_ptr<Channel> channel, std::string admin_jwt)
    {
        _stub = DDS::NewStub(channel);
        jwt = admin_jwt;
    }

    std::string import_user(secp256k1_pubkey user_public_key, int64_t signature_timestamp, int64_t expiration_timestamp, const unsigned char *signature)
    {
        unsigned char compressed_user_public_key_bytes[33];
        size_t compressed_user_public_key_len = sizeof(compressed_user_public_key_bytes);
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!secp256k1_ec_pubkey_serialize(ctx, compressed_user_public_key_bytes, &compressed_user_public_key_len, &user_public_key, SECP256K1_EC_COMPRESSED))
        {
            throw std::invalid_argument("Cannot serialize user public key");
        }

        UserConsent request;
        request.set_public_key(compressed_user_public_key_bytes, compressed_user_public_key_len);
        request.set_signature_timestamp(signature_timestamp);
        request.set_expiration_timestamp(expiration_timestamp);
        request.set_signature(signature, 64);

        Jwt response;
        ClientContext context;
        context.AddMetadata("authorization", this->jwt);
        Status status;
        status = _stub->ImportUser(&context, request, &response);
        if (status.ok())
        {
            return response.jwt();
        }
        else
        {
            // return "bad";
            throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
        }
    }

    std::tuple<std::string, secp256k1_pubkey> request_core_info()
    {
        // Request(Empty)
        Empty request;

        // Send req
        CoreInfo response;
        ClientContext context;
        context.AddMetadata("authorization", this->jwt);
        Status status;
        status = _stub->RequestCoreInfo(&context, request, &response);

        // Handle response
        if (status.ok())
        {
            secp256k1_pubkey core_public_key;
            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            std::string compressed_core_public_key = response.core_public_key();
            unsigned char compressed_core_public_key_bytes[33] = {0};
            std::memcpy(compressed_core_public_key_bytes, compressed_core_public_key.data(), compressed_core_public_key.length());
            if (!secp256k1_ec_pubkey_parse(ctx, &core_public_key, compressed_core_public_key_bytes, sizeof(compressed_core_public_key_bytes)))
                throw std::invalid_argument("The public key could not be decoded in compressed serialized format");
            return std::make_tuple(response.mq_uri(), core_public_key);
        }
        else
        {
            throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
        }
    }

private:
    std::unique_ptr<DDS::Stub> _stub;
    std::string jwt;
};

std::vector<std::string> split(const std::string &s, char delim)
{
    std::stringstream ss(s);
    std::string item;
    std::vector<std::string> elems;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
        // elems.push_back(std::move(item)); // if C++11 (based on comment from @mchiasson)
    }
    return elems;
}
auto DecodeBase64(const std::string &to_decode) -> std::string
{
    const auto predicted_len = 3 * to_decode.length() / 4; // predict output size
    const auto output_buffer{std::make_unique<char[]>(predicted_len + 1)};
    const std::vector<unsigned char> vec_chars{to_decode.begin(), to_decode.end()}; // convert to_decode into uchar container
    const auto output_len = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(output_buffer.get()), vec_chars.data(), static_cast<int>(vec_chars.size()));
    if (predicted_len != static_cast<unsigned long>(output_len))
    {
        throw std::runtime_error("DecodeBase64 error");
    }
    return output_buffer.get();
}

struct JWT decode_jwt_without_validation(std::string jwt)
{
    std::vector<std::string> splitted_jwt = split(jwt, '.');
    std::string decoded = base64_decode(splitted_jwt[1]);
    //std::cout << decoded <<std::endl;
    nlohmann::json json_JWT = nlohmann::json::parse(decoded);
    struct JWT structed_JWT = json_JWT.get<struct JWT>(); 
    //std::cout << structed_JWT.user_id << std::endl;
    return structed_JWT;
}

std::tuple<int64_t, const unsigned char *> prepare_import_user_signature(secp256k1_pubkey user_pub_key, const unsigned char *user_sec_key, secp256k1_pubkey core_pub_key, int64_t expiration_timestamp)
{
    int64_t signature_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    //int64_t signature_timestamp = 1651537665;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char compressed_core_pubkey[33];
    unsigned char compressed_user_pubkey[33];
    size_t compressed_pubkey_len;
    compressed_pubkey_len = sizeof(compressed_core_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_core_pubkey, &compressed_pubkey_len, &core_pub_key, SECP256K1_EC_COMPRESSED))
    {
        throw std::invalid_argument("Invalid core public key passed");
    }
    compressed_pubkey_len = sizeof(compressed_user_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_user_pubkey, &compressed_pubkey_len, &user_pub_key, SECP256K1_EC_COMPRESSED))
    {
        throw std::invalid_argument("Invalid core public key passed");
    }
    unsigned char signature_time_stamp_bytes[sizeof(signature_timestamp)];

    std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&signature_timestamp)),
              static_cast<const unsigned char *>(static_cast<const void *>(&signature_timestamp)) + sizeof signature_timestamp,
              signature_time_stamp_bytes);
    unsigned char expiration_time_stamp_bytes[sizeof(expiration_timestamp)];
    std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&expiration_timestamp)),
              static_cast<const unsigned char *>(static_cast<const void *>(&expiration_timestamp)) + sizeof expiration_timestamp,
              expiration_time_stamp_bytes);
    unsigned char msg[sizeof(expiration_timestamp) + sizeof(signature_timestamp) + sizeof(compressed_core_pubkey) + sizeof(compressed_user_pubkey)];
    memcpy(msg, compressed_user_pubkey, sizeof(compressed_user_pubkey));
    memcpy(msg + sizeof(compressed_user_pubkey), signature_time_stamp_bytes, sizeof(signature_time_stamp_bytes));
    memcpy(msg + sizeof(compressed_user_pubkey) + sizeof(signature_time_stamp_bytes), expiration_time_stamp_bytes, sizeof(expiration_time_stamp_bytes));
    memcpy(msg + sizeof(compressed_user_pubkey) + sizeof(signature_time_stamp_bytes) + sizeof(expiration_time_stamp_bytes), compressed_core_pubkey, sizeof(compressed_core_pubkey));
    unsigned char msg_hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, sizeof(msg), msg_hash);
    // std::cout << msg_hash;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, user_sec_key, NULL, NULL))
    {
        throw std::invalid_argument("Cannot sign the message");
    }
    unsigned char serialized_signature[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
    return std::make_tuple(signature_timestamp, serialized_signature);
}

secp256k1_pubkey generate_user(unsigned char *seckey)
{
    secp256k1_pubkey user_public_key;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    while (1)
    {
        if (!fill_random(seckey, 32))
        {
            throw std::invalid_argument("Failed to generate randomness\n");
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey))
        {
            break;
        }
    }
    if (!secp256k1_ec_pubkey_create(ctx, &user_public_key, seckey))
        throw std::invalid_argument("Cannot create publickey");
    return user_public_key;
}

int main(int argc, char **argv)
{
    std::string server_address{"127.0.0.1:8027"};
    // std::string jwt = argv[1];
    std::string core_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNzc0ODAyfQ.f6Bd-LQR57_EXdQtb6tyxDbKWalyCyNy51HEqKSYGDo";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), core_jwt};
    int64_t expiration_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 86400 *31;
    //int64_t expiration_timestamp = 1651537665 + 86400 * 31;
    secp256k1_pubkey core_public_key;
    std::string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();

    unsigned char seckey[32];
    secp256k1_pubkey user_public_key = generate_user(seckey);
    std::int64_t signature_timestamp;
    const unsigned char *serialized_signature;
    std::tie(signature_timestamp, serialized_signature) = prepare_import_user_signature(user_public_key, seckey, core_public_key, expiration_timestamp);
    std::string jwt = client.import_user(user_public_key, signature_timestamp, expiration_timestamp, serialized_signature);
    std::cout << jwt << std::endl;
    decode_jwt_without_validation(jwt);
    return 0;
}
