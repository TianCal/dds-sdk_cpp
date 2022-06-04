#include <grpc++/grpc++.h>
#include "colink_sdk_a.h"
#include "colink_sdk_p.h"
using namespace colink;
class Initiator : public ProtocolEntry
{
public:
    void start(DDSClient cl, std::string param, std::vector<Participant> participants)
    {
        std::cout << "Initiator" << std::endl;
    }
};

class Receiver : public ProtocolEntry
{
public:
    void start(DDSClient cl, std::string param, std::vector<Participant> participants)
    {
        std::cout << "Receiver, received: " << param << std::endl;
        cl.create_entry("tasks:" + cl.get_task_id() + ":output", param);
    }
};

int main(int argc, char **argv)
{
    DDSClient cl = _colink_parse_args(argc, argv);
    std::map<std::string, ProtocolEntry *> user_funcs;
    user_funcs["greetings:initiator"] = new Initiator();
    user_funcs["greetings:receiver"] = new Receiver();
    colink::_protocl_start(cl, user_funcs);
    return 0;
}