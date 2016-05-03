/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_AES_HPP_
#define INCLUDE_CRYPTOCONTAINER_AES_HPP_

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>  // Random
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#include <string>

namespace cc {
namespace cp = CryptoPP;

class CryptWrapper {
 public:
    CryptWrapper();
    void test();
};

// Generate a random key using maximum length
cp::SecByteBlock generateRandomAESKey() {
    cp::AutoSeededRandomPool rnd;
    cp::SecByteBlock key(0x00, cp::AES::MAX_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());
    return key;
}

// Generate a random initialization vector
cp::SecByteBlock generateRandomIV() {
    cp::AutoSeededRandomPool rnd;
    cp::SecByteBlock iv(0x00, cp::AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, cp::AES::BLOCKSIZE);
    return iv;
}


// Encrypt file to ostream
// @@ TODO: Should encode filebuf (ostream) to filebuf?
unsigned int encryptFileToOstream(cp::SecByteBlock key, cp::SecByteBlock iv,
                                  std::string originFilename,
                                  std::string targetFilename) {
    cp::CBC_Mode<cp::AES>::Encryption enc(key, key.size(), iv);

    // This objects deleted in fileSource pipeline object
    cp::StreamTransformationFilter* filter = new cp::StreamTransformationFilter(
        enc, new cp::FileSink(targetFilename.c_str(), true));

    CryptoPP::FileSource fileSource(originFilename.c_str(), false, filter);


    int totalBytesEncoded = 0;
    while (!fileSource.SourceExhausted()) {
        const int pumped = fileSource.Pump(cp::AES::BLOCKSIZE);
        totalBytesEncoded += pumped;

        if (pumped == 0) {
            break;
        }
    }

    // Call end of message (encrypt last part)
    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    if (totalBytesEncoded % cp::AES::MAX_KEYLENGTH != 0) {
        totalBytesEncoded = (((totalBytesEncoded + cp::AES::MAX_KEYLENGTH - 1) /
            cp::AES::MAX_KEYLENGTH) * cp::AES::MAX_KEYLENGTH);
    }

    return totalBytesEncoded;
}

// Decrypt ostream to file
void decrtyptOstreamToFile(cp::SecByteBlock key,
                           cp::SecByteBlock iv,
                           std::string originFilename,
                           std::string targetFilename,
                           unsigned int bytesToDecrypt) {
    cp::CBC_Mode<cp::AES>::Decryption dec(key, key.size(), iv);


    cp::StreamTransformationFilter* const filter =
        new cp::StreamTransformationFilter(dec,
            new cp::FileSink(targetFilename.c_str(), true));
    CryptoPP::FileSource fileSource(originFilename.c_str(), false, filter);

    int totalBytesEncoded = 0;
    while (!fileSource.SourceExhausted()) {
        const int pumped = fileSource.Pump(cp::AES::BLOCKSIZE);
        totalBytesEncoded += pumped;

        if (totalBytesEncoded - bytesToDecrypt == 0) {
            break;
        }
    }

    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
}
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_AES_HPP_
