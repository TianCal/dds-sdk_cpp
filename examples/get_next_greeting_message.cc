#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "lib.h"
#include <chrono>
using namespace colink;

int main(int argc, char **argv)
{
    using std::string;
    using namespace dds;
    string server_address = argv[1];
    string jwt = argv[2];
    string timestamp_str = (argc > 3) ? argv[3] : "";
    int64_t timestamp = (argc > 3) ? strtoll(timestamp_str.c_str(), NULL, 10) : std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    string latest_key = "_dds_internal:protocols:greetings:finished:latest";
    string queue_name = client.subscribe(latest_key, timestamp);
    DdsSubscriber subscriber = client.new_subscriber(queue_name);
    string data = subscriber.get_next();
    SubscriptionMessage message;
    message.ParseFromString(data); 
    if (message.change_type() != "delete") {
        Task task_id;
        task_id.ParseFromString(message.payload());
        StorageEntry read_key;
        read_key.set_key_name("tasks:" + task_id.task_id() + ":output");
        std::vector<StorageEntry> read_keys{read_key};
        std::vector<StorageEntry> res = client.read_entries(read_keys);
        StorageEntry output_entry = res[0];
        std::cout << output_entry.payload() << std::endl;
    }
    return 0;
}