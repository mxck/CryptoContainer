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

namespace cc {
// Generate a random key using maximum length
CryptoPP::SecByteBlock generateRandomAESKey();

// Generate a random initialization vector
CryptoPP::SecByteBlock generateRandomAES_IV();

// Encrypt file to ostream
uint64_t encryptFileToOstream(CryptoPP::SecByteBlock key,
                              CryptoPP::SecByteBlock iv,
                              std::string sourceFilename,
                              std::ostream* target);

// Decrypt ostream to file, until reach size of bytesToDecrypt
void decrtyptOstreamToFile(CryptoPP::SecByteBlock key,
                           CryptoPP::SecByteBlock iv,
                           std::istream* source,
                           std::string target,
                           uint64_t bytesToDecrypt);
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_AES_HPP_
