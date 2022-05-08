#ifndef SAMPLE_CLIENT_H
#define SAMPLE_CLIENT_H

#include "dds.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <tuple>
#include <optional>
#include <secp256k1.h>
#include "json.hpp"
#include <SimpleAmqpClient/SimpleAmqpClient.h>
using dds::CoreInfo;
using dds::DDS;
using dds::Empty;
using dds::Jwt;
using dds::StorageEntry;
using dds::UserConsent;
using dds::Participant;
using grpc::ClientContext;
using grpc::Status;
struct JWT
{
    std::string role;
    std::string user_id;
    int64_t exp;
};

struct DdsSubscriber {
    DdsSubscriber(std::string mq_uri, std::string queue_name){
        this->connection = AmqpClient::Channel::Open(AmqpClient::Channel::OpenOpts::FromUri(mq_uri));
        this->consumer_tag = this->connection->BasicConsume(queue_name, "");
    }

    std::string get_next() {
        AmqpClient::Envelope::ptr_t envelope = connection->BasicConsumeMessage(consumer_tag);
        connection->BasicAck(envelope);
        return envelope.get()->Message()->Body();
    }
    
    AmqpClient::Channel::ptr_t connection;
    std::string consumer_tag;
};
class DDSClient
{
public:
    DDSClient(std::shared_ptr<grpc::Channel> channel, std::string admin_jwt);
    std::string import_user(secp256k1_pubkey user_public_key, int64_t signature_timestamp, int64_t expiration_timestamp, const unsigned char *signature);
    std::string create_entry(std::string key_name, unsigned char *payload, size_t payload_size);
    std::string update_entry(std::string key_name, unsigned char *payload, size_t payload_size);
    std::string delete_entry(std::string key_name);
    std::vector<StorageEntry> read_entries(std::vector<StorageEntry> entries);
    void import_guest_jwt(std::string jwt);
    void import_core_addr(std::string user_id, std::string core_addr);
    std::tuple<std::string, secp256k1_pubkey> request_core_info();
    std::string subscribe(std::string key_name, int64_t start_timestamp);
    // TODO: fix this DdsSubscriber new_subscriber(std::string queue_name); 
    std::string refresh_token();
    std::string refresh_token_with_expiration_time(int64_t expiration_time);
    std::string run_task(std::string protocol_name, unsigned char *protocol_param, size_t protocol_param_size, std::vector<Participant> participants, bool require_agreement);
    std::string run_task_with_expiration_time(std::string protocol_name, unsigned char *protocol_param, size_t protocol_param_size, std::vector<Participant> participants, bool require_agreement, int64_t expiration_time);
    void confirm_task(std::string task_id, bool is_approved, bool is_rejected, std::string reason);
    void finish_task(std::string task_id);
private:
    std::unique_ptr<DDS::Stub> _stub;
    std::string jwt;
    std::string task_id;
};

std::vector<std::string> split(const std::string &s, char delim);
auto DecodeBase64(const std::string &to_decode) -> std::string;
JWT decode_jwt_without_validation(std::string jwt);
std::tuple<int64_t, const unsigned char *> prepare_import_user_signature(secp256k1_pubkey user_pub_key, const unsigned char *user_sec_key, secp256k1_pubkey core_pub_key, int64_t expiration_timestamp);
secp256k1_pubkey generate_user(unsigned char *seckey);

#endif