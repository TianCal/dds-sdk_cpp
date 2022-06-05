cmake_minimum_required(VERSION 3.16)
project(colinksdk VERSION 0.1.0)

find_package(Threads)
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
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
get_filename_component(colink_proto "./proto/colink.proto" ABSOLUTE)
get_filename_component(colink_proto_path "${colink_proto}" PATH)

# Generated sources
set(colink_proto_sources "${CMAKE_CURRENT_BINARY_DIR}/colink.pb.cc")
set(colink_proto_headers "${CMAKE_CURRENT_BINARY_DIR}/colink.pb.h")
set(colink_grpc_sources "${CMAKE_CURRENT_BINARY_DIR}/colink.grpc.pb.cc")
set(colink_grpc_headers "${CMAKE_CURRENT_BINARY_DIR}/colink.grpc.pb.h")
add_custom_command(
        OUTPUT "${colink_proto_sources}" "${colink_proto_headers}" "${colink_grpc_sources}" "${colink_grpc_headers}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${colink_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${colink_proto}"
        DEPENDS "${colink_proto}")
# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
# colink_grpc_proto
add_library(colink_grpc_proto
        ${colink_proto_sources}
        ${colink_proto_headers}
        ${colink_grpc_sources}
        ${colink_grpc_headers})
target_link_libraries(colink_grpc_proto
        ${_PROTOBUF_LIBPROTOBUF}
        ${_REFLECTION}
        ${_GRPC_GRPCPP})

########################################################################
# Secp256k1
include(ExternalProject)
set(SECP256K1_ROOT "${CMAKE_CURRENT_BINARY_DIR}/secp256k1")
ExternalProject_Add(libsecp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    UPDATE_COMMAND ./autogen.sh
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./configure
                        --prefix=<INSTALL_DIR>      
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    INSTALL_DIR ${SECP256K1_ROOT}
)
add_library(Secp256k1 STATIC IMPORTED)
set(SECP256K1_LIBRARY ${SECP256K1_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}secp256k1${CMAKE_STATIC_LIBRARY_SUFFIX})

set(SECP256K1_INCLUDE_DIR ${SECP256K1_ROOT}/include)
file(MAKE_DIRECTORY ${SECP256K1_INCLUDE_DIR})  # Must exist.
set_property(TARGET Secp256k1 PROPERTY IMPORTED_LOCATION ${SECP256K1_LIBRARY})
set_property(TARGET Secp256k1 PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${SECP256K1_INCLUDE_DIR})
include_directories(${SECP256K1_INCLUDE_DIR})
list(APPEND LIBRARIES ${SECP256K1_LIBRARY})
list(APPEND DEPENDENCIES libsecp256k1)

########################################################################
# https://github.com/alanxz/SimpleAmqpClient
include(ExternalProject)
set(SimpleAmqpClient_ROOT "${CMAKE_CURRENT_BINARY_DIR}/SimpleAmqpClient")
ExternalProject_Add(SimpleAmqpClient
    GIT_REPOSITORY https://github.com/alanxz/SimpleAmqpClient.git
    GIT_TAG master
    UPDATE_COMMAND ""
    CMAKE_ARGS  -Wno-dev 
                -DCMAKE_INSTALL_PREFIX=${SimpleAmqpClient_ROOT}
    BUILD_COMMAND make
    INSTALL_COMMAND sudo make install
)
set(SimpleAmqpClient_LIBRARY ${SimpleAmqpClient_ROOT}/lib/libSimpleAmqpClient${CMAKE_SHARED_LIBRARY_SUFFIX})
set(SimpleAmqpClient_INCLUDE_DIR ${SimpleAmqpClient_ROOT}/include)
file(MAKE_DIRECTORY ${SimpleAmqpClient_INCLUDE_DIR})  # Must exist.
include_directories(${SimpleAmqpClient_INCLUDE_DIR})
list(APPEND LIBRARIES ${SimpleAmqpClient_LIBRARY})
list(APPEND DEPENDENCIES SimpleAmqpClient)

find_package(Boost 1.47.0 COMPONENTS chrono system REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

########################################################################
add_library(libcolinksdk "src/colink_sdk_a.cc" "src/colink_sdk_p.cc")
target_link_libraries(libcolinksdk
    colink_grpc_proto
    ${_PROTOBUF_LIBPROTOBUF}
    ${_REFLECTION}
    ${_GRPC_GRPCPP})
target_link_libraries(libcolinksdk ${LIBRARIES})
add_dependencies(libcolinksdk ${DEPENDENCIES}) 

include_directories(src)
include_directories(thirdparty)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

install(TARGETS libcolinksdk
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(TARGETS libcolinksdk DESTINATION lib)
install(FILES "src/colink_sdk_a.h" DESTINATION include)
install(FILES ${colink_grpc_headers} DESTINATION include)
install(FILES ${colink_proto_headers} DESTINATION include)
install(DIRECTORY thirdparty/ DESTINATION include FILES_MATCHING PATTERN "*.h")
install(DIRECTORY thirdparty/ DESTINATION include FILES_MATCHING PATTERN "*.hpp")