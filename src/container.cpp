/* Copyright 2016 - mxck */

#include <CryptoContainer/container.hpp>

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

cc::ContainerAES::ContainerAES() {}

void cc::ContainerAES::addFile(std::string path) {
    pathsToAdd.insert(path);
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

    for (auto& entry : directory) {
        std::cout << entry.second.filename << std::endl;
    }
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
