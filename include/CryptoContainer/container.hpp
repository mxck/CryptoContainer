/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
#define INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_

#include <cryptopp/hex.h>
#include <cryptopp/rsa.h>

#include <map>
#include <set>
#include <string>
#include <list>
#include <utility>

#include <CryptoContainer/aes.hpp>
#include <CryptoContainer/utils.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

namespace cc {
struct DirectoryEntry {
    std::string filename;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock iv;
    int64_t startPos;
    int64_t sizeInBytes;

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

class Container {
 private:
    static int signSize;

    Container();

    std::filebuf fileBuf;
    std::unique_ptr<std::iostream> fileStream;  // @@ Remove this


    std::map<std::string, cc::DirectoryEntry> directory;

    // This need to set after each file save or read
    int64_t lastWritePos;

    std::unique_ptr<CryptoPP::RSA::PublicKey> publicKey;

    // First - original path, second - stored path
    std::map<std::string, std::string> filesToAdd;
    void addFileToQueue(std::string path, std::string relativeTo = "");

    void writeFile(std::pair<std::string, std::string> paths);
    void writeDirectoryAndSign();

 public:
    void addFileOrFolder(std::string path);
    void save();
    const std::map<std::string, cc::DirectoryEntry>& getDirectory() const;
    // void unpackFile(std::string path);
    // void unpackAll(std::string pathToDir);

    static std::unique_ptr<Container> openExistedContainer(
        std::string path,
        CryptoPP::RSA::PublicKey publicKey,
        CryptoPP::RSA::PrivateKey privateKey);

    static std::unique_ptr<Container> openNewContainer(
        std::string path, CryptoPP::RSA::PublicKey publicKey);
};
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_CONTAINER_HPP_
