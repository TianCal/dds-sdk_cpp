#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "lib.h"
using namespace colink;

int main(int argc, char **argv)
{
    using std::string;
    using namespace dds;
    string server_address = argv[1];
    string jwt_a = argv[2];
    string jwt_b = argv[3];
    string msg = (argc > 4) ? argv[4] : "hello";
    string user_id_a = decode_jwt_without_validation(jwt_a).user_id;
    string user_id_b = decode_jwt_without_validation(jwt_b).user_id;

    Participant initiator;
    initiator.set_user_id(user_id_a);
    initiator.set_ptype("initiator");
    Participant receiver;
    receiver.set_user_id(user_id_b);
    receiver.set_ptype("receiver");
    std::vector<Participant> participants{initiator, receiver};
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt_a};
    string task_id = client.run_task("greetings", (unsigned char *)msg.c_str(), msg.size(), participants, true);
    std::cout << "Task " << task_id << " has been created, but it will remain in waiting status until the protocol starts." << std::endl;
    return 0;
}