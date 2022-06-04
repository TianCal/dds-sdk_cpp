#include "colink_sdk_a.h"
#include <grpc++/grpc++.h>
#include <secp256k1.h>
using namespace colink;
using std::string;

int main(int argc, char **argv)
{
    string server_address = argv[1];
    string jwt = argc == 3 ? argv[2] : "";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    secp256k1_pubkey core_public_key;
    string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();
    std::cout << core_mq_uri << std::endl;
    return 0;
}