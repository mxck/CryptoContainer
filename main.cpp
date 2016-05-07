/* Copyright 2016 - mxck */

#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>

#include <iostream>
#include <memory>
#include <string>

#include <CryptoContainer/aes.hpp>
#include <CryptoContainer/container.hpp>

int main() {
    cc::ContainerAES container;
    container.addFile("test/video.mov");
    container.addFile("test/archive.zip");
    container.addFile("test/video2.mov");
    container.save("test/crypted.lol");
    container.unpack("test/crypted.lol");
    return 0;
}
