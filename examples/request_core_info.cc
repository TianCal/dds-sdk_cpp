#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "../sample_client.h"

int main(int argc, char **argv)
{
    using std::string;
    string server_address = argv[1];
    string jwt = "";
    if (argc == 3)
        jwt = argv[2];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    secp256k1_pubkey core_public_key;
    string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();
    std::cout << core_mq_uri << std::endl;
    return 0;
}