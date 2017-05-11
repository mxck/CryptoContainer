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

cc::Container::Container() {}

int cc::Container::signSize = 512;

void cc::Container::addFileToQueue(std::string path, std::string relativeTo) {
    if (!boost::filesystem::exists(path)) {
        return;
    }

    if (boost::filesystem::is_directory(path)) {
        boost::filesystem::recursive_directory_iterator dirItt(path);

        const boost::filesystem::path normalizedRelativeToPath =
            boost::filesystem::path(path).parent_path();

        for (auto& dirPath : dirItt) {
            if (!boost::filesystem::is_regular_file(dirPath)) {
                continue;
            }

            addFileToQueue(dirPath.path().string(),
                           normalizedRelativeToPath.string());
        }

        return;
    }

    boost::filesystem::path filePath(path);

    if (relativeTo.size()) {
        filePath = boost::filesystem::relative(filePath, relativeTo);
    }

    filesToAdd.insert(std::make_pair(path, filePath.string()));
}

void cc::Container::writeFile(std::pair<std::string, std::string> paths) {
    if (!boost::filesystem::exists(paths.first)
        || !boost::filesystem::is_regular_file(paths.first)) {
        return;
    }

    // Check if file alredy exists in container
    if (directory.find(paths.second) != directory.end()) {
        return;
    }

    fileStream->seekp(lastWritePos);

    // Open file
    std::filebuf fb;
    fb.open(paths.first.c_str(), std::ios::in);
    std::unique_ptr<std::istream> input =
        std::make_unique<std::istream>(&fb);

    // Create new directory entry
    cc::DirectoryEntry entry;

    // Store relative path
    entry.filename = paths.second;
    entry.startPos = fileStream->tellg();
    entry.key = cc::generateRandomAESKey();
    entry.iv = cc::generateRandomAES_IV();

    cc::EncryptAES encrypter(entry.key, entry.iv,
                             input.get(), fileStream.get());
    encrypter.pumpAll();
    entry.sizeInBytes = encrypter.getBytesCoded();

    directory.insert(std::make_pair(paths.second, entry));

    lastWritePos = fileStream->tellp();
}

void cc::Container::save() {
    if (!filesToAdd.size()) {
        return;
    }

    for (const auto& paths : filesToAdd) {
        writeFile(paths);
    }

    filesToAdd.clear();

    if (!directory.size()) {
        return;
    }

    writeDirectoryAndSign();
}

void cc::Container::writeDirectoryAndSign() {
    if (!directory.size() || !publicKey) {
        return;
    }

    fileStream->seekp(lastWritePos);

    // Convert directory to string
    std::stringstream ss;
    // Disable archive header for security reasons
    boost::archive::binary_oarchive oarch(
        ss, boost::archive::archive_flags::no_header);
    oarch << directory;

    CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
    CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();

    // Write crypted directory
    std::stringbuf stringBuf(ss.str());
    std::unique_ptr<std::istream> in =
        std::make_unique<std::istream>(&stringBuf);
    cc::EncryptAES encrypter(key, iv, in.get(), fileStream.get());
    encrypter.pumpAll();
    int64_t directorySize = encrypter.getBytesCoded();

    // Create sign
    std::stringstream enctyptedSign;
    enctyptedSign << cc::SecByteBlockToString(key);
    enctyptedSign << cc::SecByteBlockToString(iv);
    enctyptedSign << std::setfill('0') << std::setw(19) << directorySize;
    std::string cryptedSign = cc::encryptStringRSA(*publicKey,
                                                   enctyptedSign.str());

    // Write crypted sign
    fileStream->write(cryptedSign.c_str(), cc::Container::signSize);
}

void cc::Container::addFileOrFolder(std::string path) {
    addFileToQueue(path);
}

std::unique_ptr<cc::Container> cc::Container::openNewContainer(
    std::string path, CryptoPP::RSA::PublicKey publicKey) {
    std::unique_ptr<cc::Container> container(new cc::Container());

    container->publicKey =
        std::make_unique<CryptoPP::RSA::PublicKey>(publicKey);

    boost::filesystem::path p(path);
    if (p.has_parent_path()) {
        boost::filesystem::create_directories(p.parent_path());
    }

    std::ios::openmode fileFlags =
        std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc;


    container->fileBuf.open(path, fileFlags);
    container->fileStream =
        std::make_unique<std::iostream>(&container->fileBuf);

    container->lastWritePos = 0;

    return std::unique_ptr<cc::Container>(container.release());
}

std::unique_ptr<cc::Container> cc::Container::openExistedContainer(
        std::string path,
        CryptoPP::RSA::PublicKey publicKey,
        CryptoPP::RSA::PrivateKey privateKey) {
    if (!boost::filesystem::exists(path)
        || boost::filesystem::file_size(path) < cc::Container::signSize) {
        return nullptr;
    }

    std::unique_ptr<cc::Container> container(new cc::Container());

    // Set public key
    container->publicKey =
        std::make_unique<CryptoPP::RSA::PublicKey>(publicKey);

    std::ios::openmode fileFlags =
        std::ios::in | std::ios::out | std::ios::binary;

    // Create filestream and open file
    container->fileBuf.open(path, fileFlags);
    container->fileStream =
        std::make_unique<std::iostream>(&container->fileBuf);

    // Set stream read possition
    container->fileStream->seekg(-cc::Container::signSize, std::ios::end);

    // Read sign
    std::string sign(cc::Container::signSize, ' ');
    container->fileStream->read(&sign[0], cc::Container::signSize);

    // Decrypt sign
    sign = cc::decryptStringRSA(privateKey, sign);

    // Read key
    const std::string keyString = sign.substr(0, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::SecByteBlock key = cc::SecByteBlockFromString(keyString);

    // Read IV
    const std::string ivString = sign.substr(
        CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
    CryptoPP::SecByteBlock iv = cc::SecByteBlockFromString(ivString);

    // Read directory size
    const int64_t size = std::stoi(sign.substr(
        CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE, 19));

    container->fileStream->seekg(
        -cc::Container::signSize - size, std::ios::end);

    // Set last write possition
    container->lastWritePos = container->fileStream->tellg();

    // Decrypt directory
    std::stringbuf enctyptedDirectoryString;
    std::unique_ptr<std::ostream> target =
        std::make_unique<std::ostream>(&enctyptedDirectoryString);

    cc::DecryptAES dectypter(
        key, iv, container->fileStream.get(), target.get(), size);
    dectypter.pumpAll();

    // Set directory from string
    std::stringstream ss(enctyptedDirectoryString.str());
    boost::archive::binary_iarchive iarch(
        ss, boost::archive::archive_flags::no_header);
    iarch >> container->directory;

    return std::unique_ptr<cc::Container>(container.release());
}

void cc::Container::unpackFileToDisk(const DirectoryEntry& entry,
                                     std::string targetPath) {
    boost::filesystem::path oPath(
        boost::filesystem::path(targetPath) / entry.filename);

    // Create directories to file
    boost::filesystem::path parentPath = oPath.parent_path();
    if (!parentPath.empty()) {
        boost::filesystem::create_directories(parentPath);
    }

    fileStream->seekp(entry.startPos);

    std::ios::openmode fileFlags =
        std::ios::out | std::ios::binary | std::ios::trunc;

    std::filebuf oFilebuf;
    oFilebuf.open(oPath.string(), fileFlags);
    std::unique_ptr<std::ostream> oFileStream =
        std::make_unique<std::ostream>(&oFilebuf);

    cc::DecryptAES::DecryptAES decrypt(entry.key,
                                       entry.iv,
                                       fileStream.get(),
                                       oFileStream.get(),
                                       entry.sizeInBytes);

    decrypt.pumpAll();
}

void cc::Container::unpack(std::string path, std::string targetDirectory) {
    auto directoryEntryItt = directory.find(path);

    if (directoryEntryItt == directory.end()) {
        return;
    }

    unpackFileToDisk(directoryEntryItt->second, targetDirectory);
}

void cc::Container::unpackAll(std::string path) {
    for (auto& entry : directory) {
        unpackFileToDisk(entry.second, path);
    }
}

const std::map<std::string, cc::DirectoryEntry>&
    cc::Container::getDirectory() const {
    return directory;
}
