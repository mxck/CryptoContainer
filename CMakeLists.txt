cmake_minimum_required (VERSION 3.5.0)
project (CryptoContainer)
add_executable(CryptoContainer main.cpp)

# Compile with C++11 flag
set_property(TARGET CryptoContainer PROPERTY CXX_STANDARD 11)

# Set modules path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

# CryptoPP
find_package(CryptoPP REQUIRED)
include_directories(${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(CryptoContainer ${CRYPTOPP_LIBRARIES})

# Own includes
include_directories(include)
set(SOURCE_FILES
    src/aes.cpp
)
