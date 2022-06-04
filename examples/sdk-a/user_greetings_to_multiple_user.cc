#include "colink_sdk_a.h"
#include <grpc++/grpc++.h>
#include <secp256k1.h>
using namespace colink;
using std::string;

int main(int argc, char **argv)
{
    string server_address = argv[1];
    string jwt_initiator = argv[2];
    string msg = "hello";
    string user_id_initiator = decode_jwt_without_validation(jwt_initiator).user_id;
    Participant initiator;
    initiator.set_user_id(user_id_initiator);
    initiator.set_ptype("initiator");
    std::vector<Participant> participants{initiator};
    for (int i = 3; i < argc; i++)
    {
        Participant curr_receiver;
        curr_receiver.set_user_id(decode_jwt_without_validation(argv[i]).user_id);
        curr_receiver.set_ptype("receiver");
        participants.push_back(curr_receiver);
    }
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt_initiator};
    string task_id = client.run_task("greetings", msg, participants, true);
    std::cout << "Task " << task_id
              << " has been created, but it will remain in waiting status until the protocol starts." << std::endl;
}