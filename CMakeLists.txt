cmake_minimum_required(VERSION 3.16)
project(ddssdk VERSION 0.1.0)

include(CTest)
enable_testing()

find_package(Threads)

set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")
set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
if(CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
else()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif()

find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP gRPC::grpc++)
if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
endif()

# Proto file
get_filename_component(dds_proto "./proto/dds.proto" ABSOLUTE)
get_filename_component(dds_proto_path "${dds_proto}" PATH)

# Generated sources
set(dds_proto_sources "${CMAKE_CURRENT_BINARY_DIR}/dds.pb.cc")
set(dds_proto_headers "${CMAKE_CURRENT_BINARY_DIR}/dds.pb.h")
set(dds_grpc_sources "${CMAKE_CURRENT_BINARY_DIR}/dds.grpc.pb.cc")
set(dds_grpc_headers "${CMAKE_CURRENT_BINARY_DIR}/dds.grpc.pb.h")
add_custom_command(
        OUTPUT "${dds_proto_sources}" "${dds_proto_headers}" "${dds_grpc_sources}" "${dds_grpc_headers}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${dds_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${dds_proto}"
        DEPENDS "${dds_proto}")
# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
# dds_grpc_proto
add_library(dds_grpc_proto
        ${dds_proto_sources}
        ${dds_proto_headers}
        ${dds_grpc_sources}
        ${dds_grpc_headers})
target_link_libraries(dds_grpc_proto
        ${_PROTOBUF_LIBPROTOBUF}
        ${_REFLECTION}
        ${_GRPC_GRPCPP})

foreach(_target sample_client)
    add_executable(${_target} "${_target}.cc")
    target_link_libraries(${_target}
            dds_grpc_proto
            ${_PROTOBUF_LIBPROTOBUF}
            ${_REFLECTION}
            ${_GRPC_GRPCPP})
endforeach()

add_executable(ddssdk main.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
