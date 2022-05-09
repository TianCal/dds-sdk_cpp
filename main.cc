#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <iostream>
using namespace AmqpClient;
int main()
{   
    return 0;
}


/*int main(int argc, char **argv)
{
    std::string server_address{"127.0.0.1:8080"};
    // std::string jwt = argv[1];
    std::string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNzAzMTM0fQ.1KKgJhbv7AvXDCKr4B53OmQDzOsaCwPC12kw3VHNliU";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    secp256k1_pubkey core_public_key;
    std::string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();
    std::cout << core_mq_uri << std::endl;
    return 0;
}


int main(int argc, char **argv)
{
    std::string server_address = argv[1];
    std::string jwt = argv[2];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    int64_t expiration_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 86400 *31;
    secp256k1_pubkey core_public_key;
    std::string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();

    unsigned char seckey[32];
    secp256k1_pubkey user_public_key = generate_user(seckey);

    std::int64_t signature_timestamp;
    const unsigned char *serialized_signature;
    std::tie(signature_timestamp, serialized_signature) = prepare_import_user_signature(user_public_key, seckey, core_public_key, expiration_timestamp);
    std::cout << client.import_user(user_public_key, signature_timestamp, expiration_timestamp, serialized_signature) << std::endl;
    return 0;
}
*/
/*int main(int argc, char **argv)
{
    std::string server_address{"127.0.0.1:8027"};
    // std::string jwt = argv[1];
    std::string core_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNzc0ODAyfQ.f6Bd-LQR57_EXdQtb6tyxDbKWalyCyNy51HEqKSYGDo";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), core_jwt};
    int64_t expiration_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 86400 * 31;
    // int64_t expiration_timestamp = 1651537665 + 86400 * 31;
    int num = 2;
    std::string users[num];
    for (int i = 0; i < num; i++)
    {
        secp256k1_pubkey core_public_key;
        std::string core_mq_uri;
        std::tie(core_mq_uri, core_public_key) = client.request_core_info();

        unsigned char seckey[32];
        secp256k1_pubkey user_public_key = generate_user(seckey);
        std::int64_t signature_timestamp;
        const unsigned char *serialized_signature;
        std::tie(signature_timestamp, serialized_signature) = prepare_import_user_signature(user_public_key, seckey, core_public_key, expiration_timestamp);
        users[i] = client.import_user(user_public_key, signature_timestamp, expiration_timestamp, serialized_signature);
    }

    for (int i = 0; i < num; i++)
    {
        for (int j = 0; j < num; j++)
        {
            if (i != j)
            {
                DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), users[i]};
                client.import_guest_jwt(users[j]);
                JWT jwt = decode_jwt_without_validation(users[j]);
                client.import_core_addr(jwt.user_id, server_address);
            }
        }
    }
    for (int i = 0; i < num; i++)
        std::cout << users[i] << std::endl;
    return 0;
}
*/

/*int main(int argc, char **argv)
{
    std::string protocol_name = "greetings";
    std::string server_address{"127.0.0.1:8080"};
    std::string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciIsInVzZXJfaWQiOiJBa2NPU2x5Z0VhSlZWclZkbTlpYmQwUEhpRGhZWkUwOUUza21UQk1Mbk9qdyIsImV4cCI6MTY1NDc1NDUzNX0.V4qpRdW5K8ajPy1pwvlrBJYOYZuqbMTABCfSCOBDyc4";//argv[1];
    //std::string core_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNzc0ODAyfQ.f6Bd-LQR57_EXdQtb6tyxDbKWalyCyNy51HEqKSYGDo";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    std::string list_key = "_dds_internal:protocols:" + protocol_name + ":waiting";
    std::string latest_key = "_dds_internal:protocols:" + protocol_name + ":waiting:latest";
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
    std::string queue_name = client.subscribe(latest_key, start_timestamp);
    // Step 4: set up a subscriber with the queue_name.
    DdsSubscriber subscriber = client.new_subscriber(queue_name);
    while (1)
    {
        // Step 5: process subscription message.
        std::string data = subscriber.get_next();
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
}*/