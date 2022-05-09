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