/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
#define INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_

#include <map>
#include <set>
#include <string>

#include <CryptoContainer/aes.hpp>

namespace cc {
struct DirectoryEntry {
    std::string filename;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock iv;
    uint64_t startPos;
    uint64_t sizeInBytes;
};

class ContainerAES {
 private:
    std::map<std::string, cc::DirectoryEntry> directory;
    std::set<std::string> pathsToAdd;
 public:
    ContainerAES();
    void addFile(std::string path);
    void save(std::string path);
    void unpack(std::string path);
};
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
