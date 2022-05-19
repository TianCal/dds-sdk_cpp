#include <grpc++/grpc++.h>
#include "colink_sdk.h"
using namespace colink;

int64_t get_timestamp(std::string key_path)
{
    size_t pos = key_path.rfind('@');
    std::string timestamp_str = key_path.substr(pos + 1);
    int64_t timestamp = strtoll(timestamp_str.c_str(), NULL, 10);
    return timestamp;
}

int main(int argc, char **argv)
{
    using std::string;
    using namespace dds;
    string server_address = argv[1];
    string jwt = argv[2];
    string protocol_name = argv[3];
    
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    string list_key = "_dds_internal:protocols:" + protocol_name + ":waiting";
    string latest_key = "_dds_internal:protocols:" + protocol_name + ":waiting:latest";
    // Step 1: get the list of key_path which contains the timestamp.
    StorageEntry read_key;
    read_key.set_key_name(list_key);
    std::vector<StorageEntry> read_keys{read_key};
    std::vector<StorageEntry> res = client.read_entries(read_keys);
    // Step 2: find the earliest timestamp in the list.
    int64_t start_timestamp = INT64_MAX;
    StorageEntry list_entry = res[0];
    DDSInternalTaskIDList list;
    list.ParseFromString(list_entry.payload());
    if (list.task_ids_with_key_paths_size() == 0)
    {
        start_timestamp = get_timestamp(list_entry.key_path());
    }
    else
    {
        for (DDSInternalTaskIDWithKeyPath currTask : list.task_ids_with_key_paths())
        {
            start_timestamp = std::min(start_timestamp, get_timestamp(currTask.key_path()));
        }
    }
    // Step 3: subscribe and get a queue_name.
    string queue_name = client.subscribe(latest_key, start_timestamp);
    // Step 4: set up a subscriber with the queue_name.
    DdsSubscriber subscriber = client.new_subscriber(queue_name);
    while (1)
    {
        // Step 5: process subscription message.
        string data = subscriber.get_next();
        SubscriptionMessage message;
        message.ParseFromString(data); 
        // Step 5.1: match the change_type.
        if (message.change_type() != "delete") {
            Task task_id;
            task_id.ParseFromString(message.payload());
            StorageEntry read_key;
            read_key.set_key_name("_dds_internal:tasks:" + task_id.task_id());
            std::vector<StorageEntry> read_keys{read_key};
            std::vector<StorageEntry> res = client.read_entries(read_keys);
            StorageEntry task_entry = res[0];
            Task task;
            task.ParseFromString(task_entry.payload());
            // IMPORTANT: Step 5.2: you must check the status of the task received from the subscription.
            if (task.status() == "waiting")
            {
                client.confirm_task(task_id.task_id(), true, false, "");
            }
        }
    }
    return 0;
}