## Installation  

1. Install gRPC (and CMake): https://grpc.io/docs/languages/cpp/quickstart/#install-grpc
2. Install Boost: ```sudo apt-get install libboost-all-dev```
3. Install rabbitMQ: ```sudo apt-get install librabbitmq-dev```
4. Compile the repo
```
mkdir build
pushd build
cmake ..
make -j
```
