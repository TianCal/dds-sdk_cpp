#include <SimpleAmqpClient/SimpleAmqpClient.h>
using namespace AmqpClient;
int main()
{   
    AmqpClient::Channel::ptr_t connection = AmqpClient::Channel::Open(Channel::OpenOpts::FromUri("amqp://cpp-test:cpp-test@localhost:5672/cpp-test"));
    std::string consumer_tag = connection->BasicConsume("cpp-test", "");
    Envelope::ptr_t envelope = connection->BasicConsumeMessage(consumer_tag);
    // To ack:
    connection->BasicAck(envelope);
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
    std::string server_address{"127.0.0.1:8027"};
    // std::string jwt = argv[1];
    std::string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoiX2FkbWluIiwiZXhwIjoxNjUxNzE1Njg3fQ.pakDhL__f6LTqM2cLna5E0Wsv7sFzU_UG8VgY_Z1UPI";
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    //int64_t expiration_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 86400 *31;
    int64_t expiration_timestamp = 1651537665 + 86400 *31;
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