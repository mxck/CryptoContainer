/* Copyright 2016 - mxck */

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <utility>
#include <string>

#include <CryptoContainer/rsa.hpp>

std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey>
    cc::generateRSAKeys() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 4096);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    return std::make_pair(privateKey, publicKey);
}

std::string cc::encryptStringRSA(CryptoPP::RSA::PublicKey publicKey,
                                 std::string input) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string result;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor,
            new CryptoPP::StringSink(result)));

    return result;
}

std::string cc::decryptStringRSA(CryptoPP::RSA::PrivateKey privateKey,
                                 std::string input) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string result;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(result)));

    return result;
}
