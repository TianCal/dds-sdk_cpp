#include <grpc++/grpc++.h>
#include "colink_sdk_a.h"
using namespace colink;
using namespace colink_sdk_a;
using std::string;

int main(int argc, char **argv)
{
    string server_address = argv[1];
    string jwt = argv[2];
    string task_id = argv[3];
    string action = (argc > 4) ? argv[4] : "approve";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};

    if (action == "approve")
    {
        client.confirm_task(task_id, true, false, "");
    }
    else if (action == "reject")
    {
        client.confirm_task(task_id, false, true, "");
    }
    else if (action == "ignore")
    {
        client.confirm_task(task_id, false, false, "");
    }
    else
    {
        std::cout << "Action not supported: " << action << std::endl;
    }
}