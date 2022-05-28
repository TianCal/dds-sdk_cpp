#include "colink_sdk_p.h"
using namespace dds;
using colink::JWT;
using colink::DdsSubscriber;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using colink::DDSClient;
using colink_sdk_p::ProtocolEntry;

colink_sdk_p::CoLinkProtocol::CoLinkProtocol(std::string protocol_and_rule, DDSClient cl, ProtocolEntry *user_func)
{
    this->protocol_and_role = protocol_and_role;
    this->cl = cl;
    this->user_func = user_func;
}

void colink_sdk_p::CoLinkProtocol::start()
{
    std::string operator_mq_key = "_internal:protocols:" + this->protocol_and_role + ":operator_mq";
    StorageEntry read_key;
    read_key.set_key_name(operator_mq_key);
    std::vector<StorageEntry> read_keys{read_key};
    std::string queue_name;
    try {
        std::vector<StorageEntry> res = this->cl.read_entries(read_keys);
        queue_name = res[0].payload();
    }
    catch (std::invalid_argument e) {
        std::string list_key = "_internal:protocols:" + this->protocol_and_role + ":started";
        std::string latest_key = "_internal:protocols:" + this->protocol_and_role + ":started:latest";
        StorageEntry read_key;
        read_key.set_key_name(list_key);
        std::vector<StorageEntry> read_keys{read_key};
        int64_t start_timestamp;
        try {
            std::vector<StorageEntry> res = this->cl.read_entries(read_keys);
            start_timestamp = INT64_MAX;
            StorageEntry list_entry = res[0];
            DDSInternalTaskIDList list;
            list.ParseFromString(list_entry.payload());
            if (list.task_ids_with_key_paths_size() == 0)
            {
                start_timestamp = colink::get_timestamp(list_entry.key_path());
            }
            else
            {
                for (DDSInternalTaskIDWithKeyPath currTask : list.task_ids_with_key_paths())
                {
                    start_timestamp = std::min(start_timestamp, colink::get_timestamp(currTask.key_path()));
                }
            }
        }
        catch (std::invalid_argument e) {
            start_timestamp = 0;
        }
        queue_name = this->cl.subscribe(latest_key, start_timestamp);
        unsigned char *queue_name_bytes;
        std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&queue_name)),
                static_cast<const unsigned char *>(static_cast<const void *>(&queue_name)) + sizeof queue_name,
                queue_name_bytes);
        this->cl.create_entry(operator_mq_key, queue_name_bytes, sizeof(queue_name));
    }
}
DDSClient _colink_parse_args(int argc, char **argv) {
    using std::string;
    string server_address = argv[1];
    string jwt = argv[2];
    DDSClient cl{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    return cl;
}

class Initiator: public ProtocolEntry {
    public:
        void start(DDSClient cl, unsigned char *param, size_t param_size, std::vector<Participant> participants) {
            std::cout << "Initiator" << std::endl;
        }
};

class Receiver: public ProtocolEntry {
    public:
        void start(DDSClient cl, unsigned char *param, size_t param_size, std::vector<Participant> participants) {
            //TODO: this might  be string?
            std::cout << "Receiver" << std::endl;
            cl.create_entry("tasks:" + cl.get_task_id() +":output", param, param_size);
        }
};

void colink_sdk_p::_protocl_start(DDSClient cl, std::map<std::string, ProtocolEntry*> user_funcs) {
    for (const auto &x : user_funcs) {
        DDSClient cl_copy = cl;
    }
}

int main(int argc, char **argv)
{
    DDSClient cl = _colink_parse_args(argc, argv);
    std::map<std::string, ProtocolEntry*> user_funcs;
    // TODO: can we pass in class instead of instances?
    user_funcs["initiator"] = new Initiator();
    user_funcs["receiver"] = new Receiver();
    //
    colink_sdk_p::_protocl_start(cl, user_funcs);
    return 0;
}