#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "lib.h"

int main(int argc, char **argv)
{
    using std::string;
    using namespace dds;
    string server_address = argv[1];
    string jwt = argv[2];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    string new_jwt = client.refresh_token();
    std::cout << "New JWT: " << new_jwt << std::endl;
}
