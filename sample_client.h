#ifndef SAMPLE_CLIENT_H
#define SAMPLE_CLIENT_H

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

using dds::CoreInfo;
using dds::DDS;
using dds::Empty;
using dds::Jwt;
using dds::StorageEntry;
using dds::UserConsent;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
struct JWT
{
    std::string role;
    std::string user_id;
    int64_t exp;
};
class DDSClient
{
public:
    DDSClient(std::shared_ptr<Channel> channel, std::string admin_jwt);
    std::string import_user(secp256k1_pubkey user_public_key, int64_t signature_timestamp, int64_t expiration_timestamp, const unsigned char *signature);
    std::tuple<std::string, secp256k1_pubkey> request_core_info();
    std::string create_entry(std::string key_name, unsigned char *payload, size_t payload_size);
    void import_guest_jwt(std::string jwt);
    void import_core_addr(std::string user_id, std::string core_addr);

private:
    std::unique_ptr<DDS::Stub> _stub;
    std::string jwt;
};

std::vector<std::string> split(const std::string &s, char delim);
auto DecodeBase64(const std::string &to_decode) -> std::string;
JWT decode_jwt_without_validation(std::string jwt);
std::tuple<int64_t, const unsigned char *> prepare_import_user_signature(secp256k1_pubkey user_pub_key, const unsigned char *user_sec_key, secp256k1_pubkey core_pub_key, int64_t expiration_timestamp);
secp256k1_pubkey generate_user(unsigned char *seckey);

#endif