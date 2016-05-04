cmake_minimum_required (VERSION 3.3)
project (CryptoContainer)

# Own includes
set(SOURCE_FILES
    main.cpp
    src/aes.cpp
    include/CryptoContainer/aes.hpp
)

include_directories(include src)
add_executable(CryptoContainer ${SOURCE_FILES})

# Compile with C++11 flag
set_property(TARGET CryptoContainer PROPERTY CXX_STANDARD 11)

# Set modules path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

# CryptoPP
find_package(CryptoPP REQUIRED)
include_directories(${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(CryptoContainer ${CRYPTOPP_LIBRARIES})

