/* Copyright 2016 - mxck */

#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>

#include <iostream>
#include <memory>
#include <string>
#include <set>

#include <CryptoContainer/aes.hpp>
#include <CryptoContainer/rsa.hpp>
#include <CryptoContainer/container.hpp>

int main() {
    auto RSAKeys = cc::generateRSAKeys();
    {
        auto container = cc::Container::openNewContainer(
            "test/archive", RSAKeys.second);

        if (!container) {
            std::cout << "lol" << std::endl;
        }

        std::set<std::string> test;
        test.insert("test/test.txt");
        // test.insert("test/video.mov");

        container->addFiles(test);
    }

    {
        auto container2 = cc::Container::openExistedContainer(
            "test/archive", RSAKeys.second, RSAKeys.first);
        std::set<std::string> test;
        test.insert("test/archive.zip");
        container2->addFiles(test);
    }

    auto container2 = cc::Container::openExistedContainer(
        "test/archive", RSAKeys.second, RSAKeys.first);


    const auto& directory = container2->getDirectory();

    for (auto& path : directory) {
        std::cout << path.first << std::endl;
    }
    // container.addFile("test/video.mov");
    // container.addFile("test/archive.zip");
    // container.addFile("test/video2.mov");
    // container.save("test/crypted.lol");
    // container.unpack("test/crypted.lol");
    return 0;
}
