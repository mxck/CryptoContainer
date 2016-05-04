/* Copyright 2016 - mxck */

#include <CryptoContainer/aes.hpp>
#include <string>
#include <iostream>

CryptoPP::SecByteBlock cc::generateRandomAES_IV() {
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock iv(0x00, CryptoPP::AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
    return iv;
}

CryptoPP::SecByteBlock cc::generateRandomAESKey() {
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::MAX_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());
    return key;
}

cc::EncryptAES::EncryptAES(std::string sourceFilename, std::ostream* target) :
                key(cc::generateRandomAESKey()),
                iv(cc::generateRandomAES_IV()),
                encryption(Encryption(key, key.size(), iv)),
                totalBytesEncoded(0),
                eof(false),
                finalized(false) {
    filter = new CryptoPP::StreamTransformationFilter(
        encryption, new CryptoPP::FileSink(*target));
    fileSource = std::make_unique<CryptoPP::FileSource>(
        sourceFilename.c_str(), false, filter);
}

void cc::EncryptAES::finalize() {
    if (finalized) {
        return;
    }

    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    // Round totalBytesEncoded to be divisible by blocksize
    if (totalBytesEncoded % CryptoPP::AES::BLOCKSIZE != 0) {
        totalBytesEncoded =
            (((totalBytesEncoded + CryptoPP::AES::BLOCKSIZE - 1) /
            CryptoPP::AES::MAX_KEYLENGTH) *
            CryptoPP::AES::MAX_KEYLENGTH);
    }
}

void cc::EncryptAES::pump() {
    if (eof) {
        return;
    }

    uint64_t pumped = fileSource->Pump(CryptoPP::AES::BLOCKSIZE);

    if (pumped == 0) {
        eof = true;
        return;
    }

    totalBytesEncoded += pumped;
}

void cc::EncryptAES::pumpAll() {
    if (eof) {
        return;
    }

    while (!eof) {
        pump();
    }

    finalize();
}

uint64_t cc::EncryptAES::getTotalBytesEncoded() const {
    return totalBytesEncoded;
}


void cc::decrtyptOstreamToFile(CryptoPP::SecByteBlock key,
                               CryptoPP::SecByteBlock iv,
                               std::istream* source,
                               std::string target,
                               uint64_t bytesToDecrypt) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec(key, key.size(), iv);

    // Filesource get owning of filter, so no need to delete it
    CryptoPP::StreamTransformationFilter* const filter =
        new CryptoPP::StreamTransformationFilter(
            dec, new CryptoPP::FileSink(target.c_str(), true));

    CryptoPP::FileSource fileSource(*source, false, filter);

    uint64_t totalBytesEncoded = 0;
    while (!fileSource.SourceExhausted()) {
        uint64_t pumped = fileSource.Pump(CryptoPP::AES::BLOCKSIZE);

        if (pumped == 0) {
            // @@ TODO: Select the most appropriate error or create own
            throw std::runtime_error("Error: End of file");
        }

        totalBytesEncoded += pumped;

        if (totalBytesEncoded - bytesToDecrypt <= 0) {
            break;
        }
    }

    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
}
