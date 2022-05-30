## CoLink SDK for Application / for Protocol
CoLink SDK-A provides a toolkit for application developers which allows them to update storage, manage computation requests, and monitor CoLink server status.
CoLink SDK-P provides a toolkit for protocol developers which allows them to write CoLink Extensions that extend the functionality of CoLink to support new protocols.
### Installation  

1. Install gRPC (and CMake): https://grpc.io/docs/languages/cpp/quickstart/#install-grpc
2. Install Boost: ```sudo apt-get install libboost-all-dev```
3. Install rabbitMQ: ```sudo apt-get install librabbitmq-dev```
4. Compile the repo with following commands:
```
mkdir build
pushd build
cmake ..
make -j
```

### SDK-A Examples
```
./admin_import_user <address> <admin_jwt> 
```
```
./admin_import_users_and_exchange_guest_jwts <address> <admin_jwt> <number>
```
```
./user_confirm_task <address> <user_jwt> <task_id> <action> # <action>: approve(default)/reject/ignore
```
```
./user_import_guest_jwt <address> <user_jwt> <guest_jwt>
```
```
./user_refresh_token <address> <user_jwt>
```
```
./user_run_local_task <address> <user_jwt>
```
```
./user_run_task <address> <user_jwt A> <user_jwt B> <message> # <message> is optional
```
```
./user_greetings_to_multiple_users <address> <initiator_jwt> <receiver_jwt A> <receiver_jwt B> <receiver_jwt...
```
```
./auto_confirm <address> <user_jwt> <protocol_name>
```
```
./get_next_greeting_message <address> <user_jwt> <start_timestamp> # <start_timestamp> is optional
```
```
./request_core_info <address> <jwt> # <jwt> is optional
```

### SDK-P Examples
```
./protocol_greetings <address> <user_jwt>
```