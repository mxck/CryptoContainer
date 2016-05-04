/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_AES_HPP_
#define INCLUDE_CRYPTOCONTAINER_AES_HPP_

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>  // Random
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#include <stdint.h>
#include <string>
#include <memory>


namespace cc {
// Generate a random key using maximum length
CryptoPP::SecByteBlock generateRandomAESKey();

// Generate a random initialization vector
CryptoPP::SecByteBlock generateRandomAES_IV();

struct EncryptedAESFile {
    std::string filename;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock iv;
    uint64_t startPos;
    uint64_t sizeInBytes;
};

class EncryptAES {
 private:
    const CryptoPP::SecByteBlock key;
    const CryptoPP::SecByteBlock iv;

    // Filter will be deleted in fileSource destruction
    CryptoPP::StreamTransformationFilter* filter;
    std::unique_ptr<CryptoPP::FileSource> fileSource;

    typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption Encryption;
    Encryption encryption;

    uint64_t totalBytesEncoded;
    bool eof;
    bool finalized;
 public:
    EncryptAES(std::string sourceFilename, std::ostream* target);
    void pump();
    void finalize();
    void pumpAll();
    uint64_t getTotalBytesEncoded() const;
};

// Decrypt ostream to file, until reach size of bytesToDecrypt
void decrtyptOstreamToFile(CryptoPP::SecByteBlock key,
                           CryptoPP::SecByteBlock iv,
                           std::istream* source,
                           std::string target,
                           uint64_t bytesToDecrypt);
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_AES_HPP_
