#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "lib.h"

int main(int argc, char **argv)
{
    using std::string;
    string server_address = argv[1];
    string core_jwt = argv[2];
    int num = std::stoi(argv[3]);
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), core_jwt};
    int64_t expiration_timestamp = generate_expiration_timestamp(86400 * 31);
    string users[num];
    for (int i = 0; i < num; i++)
    {
        secp256k1_pubkey core_public_key;
        string core_mq_uri;
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