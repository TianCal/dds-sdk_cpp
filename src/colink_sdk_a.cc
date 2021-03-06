#include "colink_sdk_a.h"
#include "base64urldecode.h"
#include "colink.grpc.pb.h"
#include "secp_random.h"
#include <google/protobuf/message.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
using namespace colink;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

void colink::to_json(nlohmann::json &j, const JWT &value)
{
    j = nlohmann::json{{"role", value.role}, {"user_id", value.user_id}, {"exp", value.exp}};
}

void colink::from_json(const nlohmann::json &j, JWT &value)
{
    j.at("role").get_to(value.role);
    j.at("user_id").get_to(value.user_id);
    j.at("exp").get_to(value.exp);
}

colink::DDSClient::DDSClient(std::shared_ptr<Channel> channel, std::string admin_jwt)
{
    _stub = CoLink::NewStub(channel);
    this->channel = channel;
    jwt = admin_jwt;
}

std::string colink::DDSClient::import_user(secp256k1_pubkey user_public_key, int64_t signature_timestamp,
                                           int64_t expiration_timestamp, const unsigned char *signature)
{
    unsigned char compressed_user_public_key_bytes[33];
    size_t compressed_user_public_key_len = sizeof(compressed_user_public_key_bytes);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_user_public_key_bytes, &compressed_user_public_key_len,
                                       &user_public_key, SECP256K1_EC_COMPRESSED))
    {
        throw std::invalid_argument("Cannot serialize user public key");
    }

    UserConsent request;
    request.set_public_key(compressed_user_public_key_bytes, compressed_user_public_key_len);
    request.set_signature_timestamp(signature_timestamp);
    request.set_expiration_timestamp(expiration_timestamp);
    request.set_signature(signature, 64);

    Jwt response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->ImportUser(&context, request, &response);
    if (status.ok())
    {
        return response.jwt();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::string colink::DDSClient::refresh_token()
{
    return this->refresh_token_with_expiration_time(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() +
        86400);
}

void colink::DDSClient::set_task_id(std::string task_id)
{
    this->task_id = task_id;
}

std::string colink::DDSClient::get_task_id()
{
    return this->task_id;
}

std::string colink::DDSClient::refresh_token_with_expiration_time(int64_t expiration_time)
{
    RefreshTokenRequest request;
    request.set_expiration_time(expiration_time);
    Jwt response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->RefreshToken(&context, request, &response);

    if (status.ok())
    {
        this->jwt = response.jwt();
        return response.jwt();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::tuple<std::string, secp256k1_pubkey> colink::DDSClient::request_core_info()
{
    Empty request;
    CoreInfo response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->RequestCoreInfo(&context, request, &response);

    if (status.ok())
    {
        secp256k1_pubkey core_public_key;
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        std::string compressed_core_public_key = response.core_public_key();
        unsigned char compressed_core_public_key_bytes[33] = {0};
        std::memcpy(compressed_core_public_key_bytes, compressed_core_public_key.data(),
                    compressed_core_public_key.length());
        if (!secp256k1_ec_pubkey_parse(ctx, &core_public_key, compressed_core_public_key_bytes,
                                       sizeof(compressed_core_public_key_bytes)))
            throw std::invalid_argument("The public key could not be decoded in compressed serialized format");
        return std::make_tuple(response.mq_uri(), core_public_key);
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::string colink::DDSClient::create_entry(std::string key_name, std::string payload)
{
    StorageEntry request;
    request.set_key_name(key_name);
    request.set_payload(payload);
    StorageEntry response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->CreateEntry(&context, request, &response);
    if (status.ok())
    {
        return response.key_path();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::string colink::DDSClient::update_entry(std::string key_name, std::string payload)
{
    StorageEntry request;
    request.set_key_name(key_name);
    request.set_payload(payload);
    StorageEntry response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->UpdateEntry(&context, request, &response);
    if (status.ok())
    {
        return response.key_path();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::string colink::DDSClient::delete_entry(std::string key_name)
{
    StorageEntry request;
    request.set_key_name(key_name);
    StorageEntry response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->DeleteEntry(&context, request, &response);
    if (status.ok())
    {
        return response.key_path();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::vector<StorageEntry> colink::DDSClient::read_entries(std::vector<StorageEntry> entries)
{
    StorageEntries request;
    for (int i = 0; i < entries.size(); i++)
    {
        StorageEntry *curr_entry = request.add_entries();
        curr_entry->CopyFrom(entries[i]);
    }
    StorageEntries response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->ReadEntries(&context, request, &response);
    if (status.ok())
    {
        std::vector<StorageEntry> ret;
        for (int i = 0; i < response.entries_size(); i++)
        {
            ret.push_back(response.entries(i));
        }
        return ret;
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

void colink::DDSClient::import_guest_jwt(std::string jwt)
{
    JWT jwt_decoded = decode_jwt_without_validation(jwt);
    std::string key_name = "_internal:known_users:" + jwt_decoded.user_id + ":guest_jwt";
    this->create_entry(key_name, jwt);
}

void colink::DDSClient::import_core_addr(std::string user_id, std::string core_addr)
{
    std::string key_name = "_internal:known_users:" + user_id + ":core_addr";
    this->create_entry(key_name, core_addr);
}

std::string colink::DDSClient::run_task(std::string protocol_name, std::string protocol_param,
                                        std::vector<Participant> participants, bool require_agreement)
{
    int expiration_time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() +
        86400;
    return this->run_task_with_expiration_time(protocol_name, protocol_param, participants, require_agreement,
                                               expiration_time);
}

std::string colink::DDSClient::run_task_with_expiration_time(std::string protocol_name, std::string protocol_param,
                                                             std::vector<Participant> participants,
                                                             bool require_agreement, int64_t expiration_time)
{
    Task request;
    for (int i = 0; i < participants.size(); i++)
    {
        Participant *curr_participant = request.add_participants();
        curr_participant->CopyFrom(participants[i]);
    }
    request.set_protocol_name(protocol_name);
    request.set_protocol_param(protocol_param);
    request.set_require_agreement(require_agreement);
    request.set_expiration_time(expiration_time);
    request.set_parent_task(this->task_id);
    Task response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->CreateTask(&context, request, &response);
    if (status.ok())
    {
        return response.task_id();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

void colink::DDSClient::confirm_task(std::string task_id, bool is_approved, bool is_rejected, std::string reason)
{
    Decision decision;
    decision.set_is_approved(is_approved);
    decision.set_is_rejected(is_rejected);
    decision.set_reason(reason);
    ConfirmTaskRequest request;
    request.set_task_id(task_id);
    request.set_allocated_decision(&decision);
    Empty response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->ConfirmTask(&context, request, &response);
    Decision *to_release = request.release_decision();
    if (!status.ok())
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

void colink::DDSClient::finish_task(std::string task_id)
{
    Task request;
    request.set_task_id(task_id);
    Empty response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->FinishTask(&context, request, &response);
    if (!status.ok())
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

std::string colink::DDSClient::subscribe(std::string key_name, int64_t start_timestamp)
{
    SubscribeRequest request;
    request.set_key_name(key_name);
    request.set_start_timestamp(start_timestamp);
    MQQueueName response;
    ClientContext context;
    context.AddMetadata("authorization", this->jwt);
    Status status;
    status = _stub->Subscribe(&context, request, &response);
    if (status.ok())
    {
        return response.queue_name();
    }
    else
    {
        throw std::invalid_argument("RPC failed" + status.error_code() + std::string(":") + status.error_message());
    }
}

DdsSubscriber colink::DDSClient::new_subscriber(std::string queue_name)
{
    secp256k1_pubkey _;
    std::string core_mq_uri;
    std::tie(core_mq_uri, _) = this->request_core_info();
    DdsSubscriber subscriber{core_mq_uri, queue_name};
    return subscriber;
}

std::vector<std::string> colink::split(const std::string &s, char delim)
{
    std::stringstream ss(s);
    std::string item;
    std::vector<std::string> elems;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }
    return elems;
}

JWT colink::decode_jwt_without_validation(std::string jwt)
{
    std::vector<std::string> splitted_jwt = split(jwt, '.');
    std::string decoded = base64_decode(splitted_jwt[1]);
    nlohmann::json json_JWT = nlohmann::json::parse(decoded);
    JWT structed_JWT = json_JWT.get<JWT>();
    return structed_JWT;
}

std::tuple<int64_t, const unsigned char *> colink::prepare_import_user_signature(secp256k1_pubkey user_pub_key,
                                                                                 const unsigned char *user_sec_key,
                                                                                 secp256k1_pubkey core_pub_key,
                                                                                 int64_t expiration_timestamp)
{
    int64_t signature_timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char compressed_core_pubkey[33];
    unsigned char compressed_user_pubkey[33];
    size_t compressed_pubkey_len;
    compressed_pubkey_len = sizeof(compressed_core_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_core_pubkey, &compressed_pubkey_len, &core_pub_key,
                                       SECP256K1_EC_COMPRESSED))
    {
        throw std::invalid_argument("Invalid core public key passed");
    }
    compressed_pubkey_len = sizeof(compressed_user_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed_user_pubkey, &compressed_pubkey_len, &user_pub_key,
                                       SECP256K1_EC_COMPRESSED))
    {
        throw std::invalid_argument("Invalid core public key passed");
    }
    unsigned char signature_time_stamp_bytes[sizeof(signature_timestamp)];

    std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&signature_timestamp)),
              static_cast<const unsigned char *>(static_cast<const void *>(&signature_timestamp)) +
                  sizeof signature_timestamp,
              signature_time_stamp_bytes);
    unsigned char expiration_time_stamp_bytes[sizeof(expiration_timestamp)];
    std::copy(static_cast<const unsigned char *>(static_cast<const void *>(&expiration_timestamp)),
              static_cast<const unsigned char *>(static_cast<const void *>(&expiration_timestamp)) +
                  sizeof expiration_timestamp,
              expiration_time_stamp_bytes);
    unsigned char msg[sizeof(expiration_timestamp) + sizeof(signature_timestamp) + sizeof(compressed_core_pubkey) +
                      sizeof(compressed_user_pubkey)];
    memcpy(msg, compressed_user_pubkey, sizeof(compressed_user_pubkey));
    memcpy(msg + sizeof(compressed_user_pubkey), signature_time_stamp_bytes, sizeof(signature_time_stamp_bytes));
    memcpy(msg + sizeof(compressed_user_pubkey) + sizeof(signature_time_stamp_bytes), expiration_time_stamp_bytes,
           sizeof(expiration_time_stamp_bytes));
    memcpy(msg + sizeof(compressed_user_pubkey) + sizeof(signature_time_stamp_bytes) +
               sizeof(expiration_time_stamp_bytes),
           compressed_core_pubkey, sizeof(compressed_core_pubkey));
    unsigned char msg_hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, sizeof(msg), msg_hash);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, user_sec_key, NULL, NULL))
    {
        throw std::invalid_argument("Cannot sign the message");
    }
    unsigned char serialized_signature[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
    return std::make_tuple(signature_timestamp, serialized_signature);
}

secp256k1_pubkey colink::generate_user(unsigned char *seckey)
{
    secp256k1_pubkey user_public_key;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    while (1)
    {
        if (!fill_random(seckey, 32))
        {
            throw std::invalid_argument("Failed to generate randomness\n");
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey))
        {
            break;
        }
    }
    if (!secp256k1_ec_pubkey_create(ctx, &user_public_key, seckey))
    {
        throw std::invalid_argument("Cannot create publickey");
    }
    return user_public_key;
}

int64_t colink::generate_expiration_timestamp(int64_t seconds_from_now)
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
               .count() +
           seconds_from_now;
}

int64_t colink::get_timestamp(std::string key_path)
{
    size_t pos = key_path.rfind('@');
    std::string timestamp_str = key_path.substr(pos + 1);
    int64_t timestamp = strtoll(timestamp_str.c_str(), NULL, 10);
    return timestamp;
}