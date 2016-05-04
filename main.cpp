/* Copyright 2016 - mxck */

#include <iostream>
#include <memory>
#include <CryptoContainer/aes.hpp>

int main() {
    CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
    CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();

    std::filebuf fbCrypted;
    fbCrypted.open("test/crypt.mp4", std::ios::in|std::ios::app);
    std::unique_ptr<std::ostream> osCryptedW(new std::ostream(&fbCrypted));
    cc::EncryptAES crypt("test/test.mp4", osCryptedW.get());
    return 0;
}
