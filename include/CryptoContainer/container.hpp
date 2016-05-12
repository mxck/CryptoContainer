/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
#define INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_

#include <cryptopp/hex.h>
#include <cryptopp/rsa.h>

#include <map>
#include <set>
#include <string>

#include <CryptoContainer/aes.hpp>
#include <CryptoContainer/utils.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


namespace cc {
struct DirectoryEntry {
    std::string filename;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock iv;
    uint64_t startPos;
    uint64_t sizeInBytes;

    friend class boost::serialization::access;

    template<class Archive>
    void save(Archive & ar, const unsigned int version) const{ // NOLINT
        std::string aKey = cc::SecByteBlockToString(key);
        std::string aIV = cc::SecByteBlockToString(iv);

        ar << filename;
        ar << aKey;
        ar << aIV;
        ar << startPos;
        ar << sizeInBytes;
    }

    template<class Archive>
    void load(Archive & ar, const unsigned int version) { // NOLINT
        std::string aKey;
        std::string aIV;
        ar >> filename;
        ar >> aKey;
        ar >> aIV;
        ar >> startPos;
        ar >> sizeInBytes;

        key = cc::SecByteBlockFromString(aKey);
        iv = cc::SecByteBlockFromString(aIV);
    }

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version) { // NOLINT
        boost::serialization::split_member(ar, *this, version);
    }
};

class ContainerAES {
 private:
    std::map<std::string, cc::DirectoryEntry> directory;
    std::set<std::string> pathsToAdd;
    std::string directoryToString() const;
    void setDirectoryFromString(std::string dirString);
    void writeDirectory(std::ostream* target);
 public:
    ContainerAES();
    void addFile(std::string path);
    void save(std::string path);
    void unpack(std::string path);
};
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
