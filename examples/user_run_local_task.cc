#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "colink_sdk.h"
using namespace colink_sdk_a;

int main(int argc, char **argv)
{
    using std::string;
    using namespace colink;
    string server_address = argv[1];
    string jwt_a = argv[2];
    string msg = (argc > 3) ? argv[3] : "hello";
    string user_id_a = decode_jwt_without_validation(jwt_a).user_id;
    
    Participant initiator;
    initiator.set_user_id(user_id_a);
    initiator.set_ptype("initiator");
    std::vector<Participant> participants{initiator};
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt_a};
    string task_id = client.run_task("greetings", (unsigned char *)msg.c_str(), msg.size(), participants, false);
    std::cout << "Local task " << task_id << " has been created, but it will remain in waiting status until the protocol starts." << std::endl;
    return 0;
}