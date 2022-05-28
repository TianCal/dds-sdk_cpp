#ifndef COLINK_SDK_P_H
#define COLINK_SDK_P_H

#include "dds.grpc.pb.h"
#include "colink_sdk.h"
#include <grpc++/grpc++.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <tuple>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
using namespace dds;
using colink::DDSClient;
using grpc::ClientContext;
using grpc::Status;

namespace colink_sdk_p
{
    class ProtocolEntry
    {
    public:
        virtual void start(DDSClient cl, unsigned char *param, size_t param_size, std::vector<Participant> participants) = 0;
    };

    class CoLinkProtocol
    {
    public:
        CoLinkProtocol(std::string protocol_and_rule, DDSClient cl, ProtocolEntry *user_func);
        void start();
    private:
        std::string protocol_and_role;
        DDSClient cl;
        ProtocolEntry *user_func;
    };
    void _protocl_start(DDSClient cl, std::map<std::string, ProtocolEntry*> user_funcs);
}
#endif