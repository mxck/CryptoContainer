/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_AES_HPP_
#define INCLUDE_CRYPTOCONTAINER_AES_HPP_

#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>  // Random

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

namespace cc {
// Generate a random key using maximum length
CryptoPP::SecByteBlock generateRandomAESKey();

// Generate a random initialization vector
CryptoPP::SecByteBlock generateRandomAES_IV();

/*
  Classes used to write from stream to stream.
*/
class CryptAESBase {
 protected:
    CryptoPP::StreamTransformationFilter* filter;
    std::unique_ptr<CryptoPP::FileSource> fileSource;
    int64_t bytesCoded = 0;
    bool complete = false;
    virtual void atEOF() = 0;
 public:
    const bool& getComplete() const;
    const int64_t& getBytesCoded() const;
    void pumpAll();

    CryptAESBase() {}
    virtual void pump() = 0;
    virtual ~CryptAESBase();
};

class EncryptAES : public CryptAESBase {
 private:
    typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption Encryption;
    Encryption encryption;
    void atEOF();
 public:
    virtual void pump();
    EncryptAES(CryptoPP::SecByteBlock key,
               CryptoPP::SecByteBlock iv,
               std::istream* source,
               std::ostream* target);
    ~EncryptAES();
};

class DecryptAES : public CryptAESBase {
 private:
    typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption Decryption;
    Decryption decryption;
    void atEOF();
    int64_t bytesToDecrypt;
 public:
    virtual void pump();
    DecryptAES(CryptoPP::SecByteBlock key,
               CryptoPP::SecByteBlock iv,
               std::istream* source,
               std::ostream* target,
               int64_t bytesNeedToDecrypt);
    ~DecryptAES();
};
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_AES_HPP_
