#ifndef COLINK_SDK_P_H
#define COLINK_SDK_P_H

#include "colink.grpc.pb.h"
#include "colink_sdk.h"
#include <grpc++/grpc++.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <tuple>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
using namespace colink;
using namespace colink_sdk_a;
using grpc::ClientContext;
using grpc::Status;

namespace colink_sdk_p
{
    class ProtocolEntry
    {
    public:
        virtual void start(DDSClient cl, std::string param, std::vector<Participant> participants) = 0;
    };

    class CoLinkProtocol
    {
    public:
        CoLinkProtocol(std::string protocol_and_rule_, DDSClient cl_, ProtocolEntry *user_func_):
            protocol_and_role(protocol_and_rule_), cl(cl_), user_func(user_func_) {}
        void start();
    private:
        std::string protocol_and_role;
        DDSClient cl;
        ProtocolEntry *user_func;
    };
    void _protocl_start(DDSClient cl, std::map<std::string, ProtocolEntry*> user_funcs);
}
#endif