/* Copyright 2016 - mxck */

#ifndef INCLUDE_CRYPTOCONTAINER_UTILS_HPP_
#define INCLUDE_CRYPTOCONTAINER_UTILS_HPP_

#include <cryptopp/rsa.h>
#include <string>

namespace cc {
inline std::string SecByteBlockToString(const CryptoPP::SecByteBlock& str) {
    return std::string(reinterpret_cast<const char*>(str.data()),
                       str.size());
}

inline CryptoPP::SecByteBlock SecByteBlockFromString(const std::string& str) {
    return CryptoPP::SecByteBlock(reinterpret_cast<const byte*>(str.data()),
                       str.size());
}
}  // namespace cc


#endif  // INCLUDE_CRYPTOCONTAINER_UTILS_HPP_
