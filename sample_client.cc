#include "dds.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <memory>
#include <iostream>
#include <tuple>
#include <secp256k1.h>
using dds::CoreInfo;
using dds::DDS;
using dds::Empty;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
class DDSClient
{
public:
    DDSClient(std::shared_ptr<Channel> channel, std::string admin_jwt)
    {
        _stub = DDS::NewStub(channel);
        jwt = admin_jwt;
    }

    std::string import_user()
    {
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

int main(int argc, char **argv)
{
    std::string server_address{"127.0.0.1:8080"};
    // std::string jwt = argv[1];
    std::string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNDQyMDI1fQ.j3OuueKNw4I8LDxYoCSZIbCUarPHrdXWKOZjlQ35__Y";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    secp256k1_pubkey core_public_key;
    std::string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();
    std::cout << core_mq_uri << std::endl;
    return 0;
}