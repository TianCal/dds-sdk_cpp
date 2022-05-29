#include "colink_sdk_p.h"
#include <thread>
using namespace colink;
using namespace colink_sdk_a;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using colink_sdk_p::ProtocolEntry;

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
            CoLinkInternalTaskIDList list;
            list.ParseFromString(list_entry.payload());
            if (list.task_ids_with_key_paths_size() == 0)
            {
                start_timestamp = get_timestamp(list_entry.key_path());
            }
            else
            {
                for (CoLinkInternalTaskIDWithKeyPath currTask : list.task_ids_with_key_paths())
                {
                    start_timestamp = std::min(start_timestamp, get_timestamp(currTask.key_path()));
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
    secp256k1_pubkey _;
    std::string mq_addr;    
    std::tie(mq_addr, _) = this->cl.request_core_info();

    AmqpClient::Channel::ptr_t mq = AmqpClient::Channel::Open(AmqpClient::Channel::OpenOpts::FromUri(mq_addr));
    std::string consumer_tag = mq->BasicConsume(queue_name, "", true, false);
    mq->BasicQos(consumer_tag, 1);

    while (1) {
        AmqpClient::Envelope::ptr_t envelope = mq->BasicConsumeMessage(consumer_tag);
        mq->BasicAck(envelope);
        std::string data = envelope.get()->Message()->Body();
        SubscriptionMessage message;
        message.ParseFromString(data);
        if (message.change_type() != "delete") {
            Task task_id;
            task_id.ParseFromString(message.payload());
            StorageEntry read_key;
            read_key.set_key_name("_internal:tasks:" + task_id.task_id());
            std::vector<StorageEntry> read_keys{read_key};
            try {
                std::vector<StorageEntry> res = this->cl.read_entries(read_keys);
                StorageEntry task_entry = res[0];
                Task task;
                task.ParseFromString(task_entry.payload());
                if (task.status() == "started")
                {
                    //begin user func
                    DDSClient cl(this->cl);
                    cl.set_task_id(task_id.task_id());
                    std::string ptype = "";
                    std::string protocol_param = task.protocol_param();
                    unsigned char *protocol_param_bytes;
                    std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&protocol_param)),
                        static_cast<const unsigned char *>(static_cast<const void *>(&protocol_param)) + sizeof protocol_param,
                        protocol_param_bytes);
                    std::vector<Participant> participants;
                    for (int i = 0; i < task.participants_size(); i++) {
                        Participant participant = task.participants(i);
                        participants.push_back(participant);
                    }
                    this->user_func->start(cl, protocol_param_bytes, sizeof(protocol_param), participants);
                    this->cl.finish_task(task_id.task_id());
                }
            }
            catch (std::invalid_argument &e) {
                throw std::invalid_argument(std::string("Pull Task Error:") + e.what());
            }
        }

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
            std::cout << "Receiver" << std::endl;
            cl.create_entry("tasks:" + cl.get_task_id() +":output", param, param_size);
        }
};

void colink_sdk_p::_protocl_start(DDSClient cl, std::map<std::string, ProtocolEntry*> user_funcs) {
    std::vector<std::thread> threads;
    for (const auto &x : user_funcs) {
        DDSClient cl_copy = cl;
        CoLinkProtocol curr_protocol{x.first, cl_copy, x.second};
        //curr_protocol.start();
        threads.push_back(std::thread([](CoLinkProtocol x){x.start();}, curr_protocol));
    }
    std::cout << "Started" << std::endl;
    for (auto& t : threads)
        t.join();
}

int main(int argc, char **argv)
{
    DDSClient cl = _colink_parse_args(argc, argv);
    std::map<std::string, ProtocolEntry*> user_funcs;
    // TODO: can we pass in class instead of instances?
    user_funcs["greetings:initiator"] = new Initiator();   
    //user_funcs["receiver"] = new Receiver();
    //
    colink_sdk_p::_protocl_start(cl, user_funcs);
    return 0;
}