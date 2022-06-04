#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "colink_sdk_a.h"
using namespace colink;
using std::string;

int main(int argc, char **argv)
{
    string server_address = argv[1];
    string jwt = argv[2];
    string guest_jwt = argv[3];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    client.import_guest_jwt(guest_jwt);
    return 0;
}