/* Copyright 2016 - mxck */

#include <iostream>
#include <CryptoContainer/aes.hpp>

/*
    OSTREAM

    std::filebuf fb;
    fb.open("out_crypt.mp4", std::ios::out|std::ios::binary);
    std::ostream os(&fb);
*/

int main() {
    auto key = cc::generateRandomAESKey();
    auto iv = cc::generateRandomIV();
    int bytes = cc::encryptFileToOstream(key, iv, "test.mp4", "encrypt.mp4");
    cc::decrtyptOstreamToFile(key, iv, "encrypt.mp4", "decrypt.mp4", bytes);

    cc::CryptWrapper cryptWrapper;
    return 0;
}
