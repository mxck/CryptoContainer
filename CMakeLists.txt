cmake_minimum_required (VERSION 3.5.2)

project (CryptoDiplom)
add_executable(CryptoDiplom main.cpp)
set_property(TARGET CryptoDiplom PROPERTY CXX_STANDARD 11)


find_package(OpenSSL)
include_directories(${OPENSSL_INCLUDE_DIR})
