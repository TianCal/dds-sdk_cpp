#include "dds.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <memory>
#include <iostream>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using dds::DDS;
using dds::CoreInfo;
using dds::Empty;
class DDSClient {
public:
    DDSClient(std::shared_ptr<Channel> channel, std::string admin_jwt) {
        _stub = DDS::NewStub(channel);
        jwt = admin_jwt;
    }

    std::string request_core_info() {
        //Request(Empty)
        Empty request;

        //Send req
        CoreInfo response;
        ClientContext context;
        Status status;
        status = _stub->RequestCoreInfo(&context, request, &response);

        // Handle response
        if (status.ok()) {
            std::cout << "起飞" << std::endl;
            return "芜湖";
        } else {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            return "RPC failed";
        }
    }
private:
    std::unique_ptr<DDS::Stub> _stub;
    std::string jwt;
};
int main(int argc, char** argv) {
    std::string server_address{"http://127.0.0.1:8080"};
    std::string jwt = argv[1];
    std::cout << jwt << std::endl;
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    std::string sample_core_info = client.request_core_info();
    std::cout << sample_core_info << std::endl;
    return 0;
}