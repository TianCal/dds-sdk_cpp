#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "colink_sdk_a.h"
using namespace colink;
using namespace colink_sdk_a;
using std::string;

int main(int argc, char **argv)
{
    string server_address = argv[1];
    string jwt = argv[2];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    string new_jwt = client.refresh_token();
    std::cout << "New JWT: " << new_jwt << std::endl;
}
