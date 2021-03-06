#ifndef COLINK_SDK_A_H
#define COLINK_SDK_A_H

#include "colink.grpc.pb.h"
#include "json.hpp"
#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <chrono>
#include <grpc++/grpc++.h>
#include <iostream>
#include <secp256k1.h>
#include <string>
#include <tuple>
#include <vector>
using namespace colink;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

namespace colink
{
struct JWT
{
    std::string role;
    std::string user_id;
    int64_t exp;
};

struct DdsSubscriber
{
    DdsSubscriber(std::string mq_uri, std::string queue_name)
    {
        this->connection = AmqpClient::Channel::Open(AmqpClient::Channel::OpenOpts::FromUri(mq_uri));
        this->consumer_tag = this->connection->BasicConsume(queue_name, "", true, false);
    }

    std::string get_next()
    {
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
    DDSClient(const DDSClient &cl)
    {
        this->_stub = CoLink::NewStub(cl.channel);
        this->jwt = cl.jwt;
        this->task_id = cl.task_id;
        this->channel = cl.channel;
    }
    DDSClient(){};
    ~DDSClient(){};
    std::string import_user(secp256k1_pubkey user_public_key, int64_t signature_timestamp, int64_t expiration_timestamp,
                            const unsigned char *signature);
    std::string create_entry(std::string key_name, std::string payload);
    std::string update_entry(std::string key_name, std::string payload);
    std::string delete_entry(std::string key_name);
    std::vector<StorageEntry> read_entries(std::vector<StorageEntry> entries);
    void import_guest_jwt(std::string jwt);
    void import_core_addr(std::string user_id, std::string core_addr);
    std::tuple<std::string, secp256k1_pubkey> request_core_info();
    std::string subscribe(std::string key_name, int64_t start_timestamp);
    DdsSubscriber new_subscriber(std::string queue_name);
    std::string refresh_token();
    std::string refresh_token_with_expiration_time(int64_t expiration_time);
    std::string run_task(std::string protocol_name, std::string protocol_param, std::vector<Participant> participants,
                         bool require_agreement);
    std::string run_task_with_expiration_time(std::string protocol_name, std::string protocol_param,
                                              std::vector<Participant> participants, bool require_agreement,
                                              int64_t expiration_time);
    void confirm_task(std::string task_id, bool is_approved, bool is_rejected, std::string reason);
    void finish_task(std::string task_id);
    void set_task_id(std::string task_id);
    std::string get_task_id();

  private:
    std::unique_ptr<CoLink::Stub> _stub;
    std::string jwt;
    std::string task_id;
    std::shared_ptr<Channel> channel;
};

std::vector<std::string> split(const std::string &s, char delim);
JWT decode_jwt_without_validation(std::string jwt);
std::tuple<int64_t, const unsigned char *> prepare_import_user_signature(secp256k1_pubkey user_pub_key,
                                                                         const unsigned char *user_sec_key,
                                                                         secp256k1_pubkey core_pub_key,
                                                                         int64_t expiration_timestamp);
secp256k1_pubkey generate_user(unsigned char *seckey);
int64_t generate_expiration_timestamp(int64_t seconds_from_now);
void to_json(nlohmann::json &j, const JWT &value);
void from_json(const nlohmann::json &j, JWT &value);
int64_t get_timestamp(std::string key_path);
} // namespace colink
#endif