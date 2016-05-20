/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_RSA_HPP_
#define INCLUDE_CRYPTOCONTAINER_RSA_HPP_

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <sstream>
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

template<typename T>
inline typename isRSAKey<T>::type loadKeyFromFile(std::string filename) {
    std::ifstream in(filename);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return RSAKeyFromString<typename isRSAKey<T>::type>(buffer.str());
}

template<typename T>
inline void saveKeyToFile(std::string filename,
                          typename isRSAKey<T>::type key) {
    std::filebuf buf;
    buf.open(filename,
        std::ios::trunc | std::ios::out | std::ios::binary);
    std::ostream os(&buf);
    os << RSAKeyToString<typename isRSAKey<T>::type>(key);
}

std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey>
    generateRSAKeys();

std::string encryptStringRSA(CryptoPP::RSA::PublicKey publicKey,
                             std::string input);

std::string decryptStringRSA(CryptoPP::RSA::PrivateKey privateKey,
                             std::string input);
}  // namespace cc

#endif  // INCLUDE_CRYPTOCONTAINER_RSA_HPP_
