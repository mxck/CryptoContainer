/* Copyright 2016 - mxck */

#include <iostream>
#include <memory>
#include <CryptoContainer/aes.hpp>

/*
    OSTREAM

    std::filebuf fb;
    fb.open("out_crypt.mp4", std::ios::out|std::ios::binary);
    std::ostream os(&fb);
*/

int main() {
    CryptoPP::SecByteBlock key = cc::generateRandomAESKey();
    CryptoPP::SecByteBlock iv = cc::generateRandomAES_IV();

    std::filebuf fbCrypted;
    fbCrypted.open("test/crypt.mp4", std::ios::in|std::ios::app);
    std::unique_ptr<std::ostream> osCryptedW(new std::ostream(&fbCrypted));

    uint64_t bytes =
        cc::encryptFileToOstream(key, iv, "test/test.mp4", osCryptedW.get());


    std::unique_ptr<std::istream> osCryptedR(new std::istream(&fbCrypted));
    uint64_t pos = static_cast<uint64_t>(osCryptedR->tellg()) - bytes;
    std::cout << osCryptedR->tellg() << std::endl;
    osCryptedR->seekg(static_cast<int64_t>(pos));
    cc::decrtyptOstreamToFile(key, iv, osCryptedR.get(), "test/decrypt.mp4",
                              bytes);
    return 0;
}
