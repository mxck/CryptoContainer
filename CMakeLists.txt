cmake_minimum_required (VERSION 3.3)
project (CryptoContainer)

# Own includes
set(SOURCE_FILES
    main.cpp

    # AES
    include/CryptoContainer/aes.hpp
    src/aes.cpp

    # Container
    include/CryptoContainer/container.hpp
    src/container.cpp

    # Utils
    include/CryptoContainer/utils.hpp

    # RSA
    include/CryptoContainer/rsa.hpp
    src/rsa.cpp
)

include_directories(include src)
add_executable(CryptoContainer ${SOURCE_FILES})

# Compile with C++11 flag
set_property(TARGET CryptoContainer PROPERTY CXX_STANDARD 14)

# Set modules path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

# CryptoPP
# @@ TODO: Check this custom module at windows
find_package(CryptoPP REQUIRED)
include_directories(${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(CryptoContainer ${CRYPTOPP_LIBRARIES})

# Boost
find_package(Boost 1.60.0 REQUIRED serialization filesystem program_options)
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(CryptoContainer ${Boost_LIBRARIES})
