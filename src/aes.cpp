/* Copyright 2016 - mxck */

#include <CryptoContainer/aes.hpp>
#include <string>

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

uint64_t cc::encryptFileToOstream(CryptoPP::SecByteBlock key,
                                  CryptoPP::SecByteBlock iv,
                                  std::string sourceFilename,
                                  std::ostream* target) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc(key, key.size(), iv);

    // Filesource get owning of filter, so no need to delete it
    CryptoPP::StreamTransformationFilter* const filter =
        new CryptoPP::StreamTransformationFilter(
            enc, new CryptoPP::FileSink(*target));

    CryptoPP::FileSource fileSource(sourceFilename.c_str(), false, filter);

    uint64_t totalBytesEncoded = 0;
    while (!fileSource.SourceExhausted()) {
        uint64_t pumped = fileSource.Pump(CryptoPP::AES::BLOCKSIZE);
        totalBytesEncoded += pumped;

        if (pumped == 0) {
            break;
        }
    }

    // Call end of message (encrypt last part)
    filter->ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    // Round totalBytesEncoded to be divisible by blocksize
    if (totalBytesEncoded % CryptoPP::AES::BLOCKSIZE != 0) {
        totalBytesEncoded =
            (((totalBytesEncoded + CryptoPP::AES::BLOCKSIZE - 1) /
            CryptoPP::AES::MAX_KEYLENGTH) *
            CryptoPP::AES::MAX_KEYLENGTH);
    }

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
