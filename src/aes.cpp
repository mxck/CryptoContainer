/* Copyright 2016 - mxck */

#include <CryptoContainer/aes.hpp>

#include <iostream>
#include <string>
#include <utility>

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

/*
    CryptAESBase
*/
const bool& cc::CryptAESBase::getComplete() const {
    return complete;
}

const int64_t& cc::CryptAESBase::getBytesCoded() const {
    return bytesCoded;
}

void cc::CryptAESBase::pumpAll() {
    if (complete) {
        return;
    }

    while (!complete) {
        pump();
    }
}

cc::CryptAESBase::~CryptAESBase() {}

/*
    EncryptAES
*/
cc::EncryptAES::EncryptAES(CryptoPP::SecByteBlock key,
                           CryptoPP::SecByteBlock iv,
                           std::istream* source,
                           std::ostream* target)
    : encryption(Encryption(key, key.size(), iv)) {
    filter = new CryptoPP::StreamTransformationFilter(
        encryption, new CryptoPP::FileSink(*target));
    fileSource = std::make_unique<CryptoPP::FileSource>(*source, false, filter);
}

void cc::EncryptAES::atEOF() {
    if (complete) {
        return;
    }

    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    // Round bytesCoded to be divisible by blocksize
    if (bytesCoded % CryptoPP::AES::BLOCKSIZE != 0) {
        bytesCoded =
            (((bytesCoded + CryptoPP::AES::BLOCKSIZE - 1) /
            CryptoPP::AES::BLOCKSIZE) *
            CryptoPP::AES::BLOCKSIZE);
    }

    complete = true;
}

void cc::EncryptAES::pump() {
    if (complete) {
        return;
    }

    // @@ TODO: Move to value to const or static
    int64_t pumped = static_cast<int64_t>(fileSource->Pump(2048));

    if (pumped == 0) {
        atEOF();
        return;
    }

    bytesCoded += pumped;
}

cc::EncryptAES::~EncryptAES() {}

/*
    DecryptAES
*/
cc::DecryptAES::DecryptAES(CryptoPP::SecByteBlock key,
                           CryptoPP::SecByteBlock iv,
                           std::istream* source,
                           std::ostream* target,
                           int64_t fileSize)
    : decryption(Decryption(key, key.size(), iv)),
      bytesToDecrypt(fileSize) {
    filter = new CryptoPP::StreamTransformationFilter(
        decryption, new CryptoPP::FileSink(*target));
    fileSource = std::make_unique<CryptoPP::FileSource>(*source, false, filter);
}

void cc::DecryptAES::pump() {
    if (complete) {
        return;
    }

    int64_t pumped = static_cast<int64_t>(
        fileSource->Pump(CryptoPP::AES::BLOCKSIZE));

    if (pumped == 0 && !complete) {
        throw std::runtime_error("Error: End of file");
    }

    bytesCoded += pumped;

    if (bytesToDecrypt - bytesCoded <= 0) {
        atEOF();
    }
}

void cc::DecryptAES::atEOF() {
    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    complete = true;
}

cc::DecryptAES::~DecryptAES() {}
