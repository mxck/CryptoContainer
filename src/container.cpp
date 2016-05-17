/* Copyright 2016 - mxck */

#include <cryptopp/base64.h>

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <array>
#include <sstream>
#include <map>
#include <set>
#include <list>
#include <iomanip>

#include <CryptoContainer/container.hpp>
#include <CryptoContainer/rsa.hpp>
#include <CryptoContainer/utils.hpp>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>

#include <boost/filesystem.hpp>


// // std::string cc::Container::directoryToString() const {
//     std::stringstream ss;
//     // Disable archive header for security reasons
//     boost::archive::binary_oarchive oarch(
//         ss, boost::archive::archive_flags::no_header);
//     oarch << directory;
//     return ss.str();
// // }

// void cc::Container::setDirectoryFromString(std::string str) {
//     std::stringstream ss(str);
//     boost::archive::binary_iarchive iarch(
//         ss, boost::archive::archive_flags::no_header);
//     iarch >> directory;
// }

cc::Container::Container() {}

void cc::Container::addFiles(std::set<std::string> paths) {
    if (!paths.size()) {
        return;
    }

    fileStream->seekg(lastWritePos);
    /**
        Pack files, if file exist pack it and add to directory
    */
    for (auto& path : paths) {
        if (!boost::filesystem::exists(path) ||
            !boost::filesystem::is_regular_file(path)) {
            continue;
        }

        std::filebuf fb;
        fb.open(path.c_str(), std::ios::in);
        std::unique_ptr<std::istream> input =
            std::make_unique<std::istream>(&fb);

        cc::DirectoryEntry entry;

        entry.filename = path;
        entry.startPos = fileStream->tellg();
        entry.key = cc::generateRandomAESKey();
        entry.iv = cc::generateRandomAES_IV();

        cc::EncryptAES encrypter(entry.key, entry.iv,
                                 input.get(), fileStream.get());
        encrypter.pumpAll();
        entry.sizeInBytes = encrypter.getBytesCoded();

        directory.insert(std::make_pair(path, entry));
    }

    /**
        Save directory
    */

    if (!directory.size()) {
        return;
    }

    // Convert directory to string
    std::stringstream ss;
    // Disable archive header for security reasons
    boost::archive::binary_oarchive oarch(
        ss, boost::archive::archive_flags::no_header);
    oarch << directory;

    CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
    CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();

    std::stringbuf stringBuf(ss.str());
    std::unique_ptr<std::istream> in =
        std::make_unique<std::istream>(&stringBuf);
    cc::EncryptAES encrypter(key, iv, in.get(), fileStream.get());
    encrypter.pumpAll();
    int64_t directorySize = encrypter.getBytesCoded();

    /**
        Create sign
    */
    std::stringstream enctyptedSign;
    enctyptedSign << cc::SecByteBlockToString(key);
    enctyptedSign << cc::SecByteBlockToString(iv);
    enctyptedSign << std::setfill('0') << std::setw(19) << directorySize;
    std::string cryptedSign = cc::encryptStringRSA(*publicKey,
                                                   enctyptedSign.str());
    // std::cout << iv.data() << std::endl;
    /**
        Write sign to file
    */

    // std::cout << cryptedSign << std::endl;
    // std::cout << cryptedSign.size() << std::endl;
    fileStream->write(cryptedSign.c_str(), 512);
}

std::unique_ptr<cc::Container> cc::Container::openNewContainer(
    std::string path, CryptoPP::RSA::PublicKey publicKey) {
    std::unique_ptr<cc::Container> container(new cc::Container());

    container->publicKey =
        std::make_unique<CryptoPP::RSA::PublicKey>(publicKey);

    boost::filesystem::path p(path);
    boost::filesystem::create_directories(p.parent_path());

    std::ios::openmode fileFlags =
        std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc;


    container->fileBuf.open(path, fileFlags);
    container->fileStream =
        std::make_unique<std::iostream>(&container->fileBuf);

    return std::unique_ptr<cc::Container>(container.release());
}

std::unique_ptr<cc::Container> cc::Container::openExistedContainer(
        std::string path,
        CryptoPP::RSA::PublicKey publicKey,
        CryptoPP::RSA::PrivateKey privateKey) {
    if (!boost::filesystem::exists(path)
        || boost::filesystem::file_size(path) < 512) {
        return nullptr;
    }

    std::unique_ptr<cc::Container> container(new cc::Container());

    container->publicKey =
        std::make_unique<CryptoPP::RSA::PublicKey>(publicKey);

    std::ios::openmode fileFlags =
        std::ios::in | std::ios::out | std::ios::binary;

    container->fileBuf.open(path, fileFlags);
    container->fileStream =
        std::make_unique<std::iostream>(&container->fileBuf);

    container->fileStream->seekg(-512, std::ios::end);
    std::string test(512, ' ');
    container->fileStream->read(&test[0], 512);

    test = cc::decryptStringRSA(privateKey, test);
    // std::cout << test.size() << std::endl;

    const std::string keyString = test.substr(0, 32);
    CryptoPP::SecByteBlock key = cc::SecByteBlockFromString(keyString);
    const std::string ivString = test.substr(32, 16);
    CryptoPP::SecByteBlock iv = cc::SecByteBlockFromString(ivString);

    const int64_t size = std::stoi(test.substr(48, 19));

    container->fileStream->seekg(-512 - size, std::ios::end);
    container->lastWritePos = container->fileStream->tellg();

    std::stringbuf enctyptedDirectoryString;
    std::unique_ptr<std::ostream> target =
        std::make_unique<std::ostream>(&enctyptedDirectoryString);

    cc::DecryptAES dectypted(
        key, iv, container->fileStream.get(), target.get(), size);
    dectypted.pumpAll();

    std::stringstream ss(enctyptedDirectoryString.str());
    boost::archive::binary_iarchive iarch(
        ss, boost::archive::archive_flags::no_header);
    iarch >> container->directory;

    return std::unique_ptr<cc::Container>(container.release());
}

const std::map<std::string, cc::DirectoryEntry>&
    cc::Container::getDirectory() const {
    return directory;
}
