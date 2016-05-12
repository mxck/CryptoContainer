/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_RSA_HPP_
#define INCLUDE_CRYPTOCONTAINER_RSA_HPP_

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <string>
#include <utility>

namespace cc {
template <typename T>
struct isRSAKey {
};

template <>
struct isRSAKey<CryptoPP::RSA::PublicKey> {
    typedef CryptoPP::RSA::PublicKey type;
};

template <>
struct isRSAKey<CryptoPP::RSA::PrivateKey> {
    typedef CryptoPP::RSA::PrivateKey type;
};

template <typename T>
inline std::string RSAKeyToString(const typename isRSAKey<T>::type& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    std::string result;
    CryptoPP::StringSink sink(result);
    queue.CopyTo(sink);
    return result;
}

template <typename T>
inline typename isRSAKey<T>::type RSAKeyFromString(const std::string& str) {
    CryptoPP::StringSource stringSource(str, true);
    CryptoPP::ByteQueue queue;
    stringSource.TransferTo(queue);

    typename isRSAKey<T>::type key;
    key.Load(queue);
    return key;
}

std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey>
generateRSAKeys() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 4096);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    return std::make_pair(privateKey, publicKey);
}

std::string encryppStringRSA(CryptoPP::RSA::PublicKey publicKey, std::string input) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string result;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor,
            new CryptoPP::StringSink(result)));

    return result;
}
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_RSA_HPP_
