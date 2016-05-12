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
#include <list>
#include <iomanip>

#include <CryptoContainer/container.hpp>
#include <CryptoContainer/rsa.hpp>
#include <CryptoContainer/utils.hpp>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>


cc::ContainerAES::ContainerAES() {}

void cc::ContainerAES::addFile(std::string path) {
    // @@ Todo: Check if file or path exists
    pathsToAdd.insert(path);
}

std::string cc::ContainerAES::directoryToString() const {
    std::stringstream ss;
    // Disable archive header for security reasons
    boost::archive::binary_oarchive oarch(
        ss, boost::archive::archive_flags::no_header);
    oarch << directory;
    return ss.str();
}

void cc::ContainerAES::setDirectoryFromString(std::string dirString) {
    std::stringstream ss(dirString);
    boost::archive::binary_iarchive iarch(
        ss, boost::archive::archive_flags::no_header);
    iarch >> directory;
}

void cc::ContainerAES::writeDirectory(std::ostream* target) {
    std::stringbuf dirStringBuffer(directoryToString(), std::ios::in);
    std::unique_ptr<std::istream> directoryInputStream =
        std::make_unique<std::istream>(&dirStringBuffer);
    std::istream os(&dirStringBuffer);

    CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
    CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();
    cc::EncryptAES encrypter(key, iv, directoryInputStream.get(), target);
    encrypter.pumpAll();

    uint64_t pos = target->tellp();

    std::stringstream header;
    header << cc::SecByteBlockToString(key);
    header << cc::SecByteBlockToString(iv);
    header << std::setfill('0') << std::setw(20) << pos;
    auto keys = cc::generateRSAKeys();

    std::cout << cc::RSAKeyToString<CryptoPP::RSA::PublicKey>(keys.first) << std::endl;
    std::cout << cc::RSAKeyToString<CryptoPP::RSA::PublicKey>(keys.second) << std::endl;

    std::string h = cc::encryppStringRSA(keys.second, header.str());
    std::cout << h.size() << std::endl;
}

void cc::ContainerAES::save(std::string path) {
    std::filebuf fbContainer;
    fbContainer.open(path, std::ios::out);
    std::unique_ptr<std::ostream> osContainer(new std::ostream(&fbContainer));

    for (const auto& filePath : pathsToAdd) {
        const uint64_t startPos = static_cast<uint64_t>(osContainer->tellp());

        CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
        CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();

        std::filebuf fbSource;
        fbSource.open(filePath, std::ios::in);
        std::unique_ptr<std::istream> isTarget(new std::istream(&fbSource));

        cc::EncryptAES encrypter(key, iv, isTarget.get(), osContainer.get());
        encrypter.pumpAll();

        uint64_t totalEncoded = encrypter.getBytesCoded();

        const DirectoryEntry directoryEntry { filePath, key, iv,
                                              startPos, totalEncoded };

        directory.insert(std::pair<std::string, cc::DirectoryEntry>(
            filePath, directoryEntry));
    }

    writeDirectory(osContainer.get());

    directoryToString();
}

void cc::ContainerAES::unpack(std::string path) {
    std::filebuf fbContainer;
    fbContainer.open(path, std::ios::in);
    std::unique_ptr<std::istream> isContainer(new std::istream(&fbContainer));

    for (auto& entry : directory) {
        const std::string entryPath = "test/unpack/" + entry.second.filename;

        std::filebuf fbFile;
        fbFile.open(entryPath, std::ios::out);
        std::unique_ptr<std::ostream> osFile(new std::ostream(&fbFile));

        isContainer->seekg(static_cast<int64_t>(entry.second.startPos));

        cc::DecryptAES decrypt(entry.second.key,
                               entry.second.iv,
                               isContainer.get(),
                               osFile.get(),
                               entry.second.sizeInBytes);
        decrypt.pumpAll();
    }
}
