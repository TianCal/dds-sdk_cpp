#include <secp256k1.h>
#include <grpc++/grpc++.h>
#include "../sample_client.h"

int main(int argc, char **argv)
{
    using std::string;
    string server_address = argv[1];
    string jwt = argv[2];
    DDSClient client{grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()), jwt};
    int64_t expiration_timestamp = generate_expiration_timestamp(86400 * 31);
    secp256k1_pubkey core_public_key;
    string core_mq_uri;
    std::tie(core_mq_uri, core_public_key) = client.request_core_info();

    unsigned char seckey[32];
    secp256k1_pubkey user_public_key = generate_user(seckey);

    std::int64_t signature_timestamp;
    const unsigned char *serialized_signature;
    std::tie(signature_timestamp, serialized_signature) = prepare_import_user_signature(user_public_key, seckey, core_public_key, expiration_timestamp);
    std::cout << client.import_user(user_public_key, signature_timestamp, expiration_timestamp, serialized_signature) << std::endl;
    return 0;
}