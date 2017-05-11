/* Copyright 2016 - mxck */

#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>

#include <iostream>
#include <memory>
#include <string>
#include <set>
#include <vector>

#include <CryptoContainer/aes.hpp>
#include <CryptoContainer/rsa.hpp>
#include <CryptoContainer/container.hpp>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

int main(int argc, char *argv[]) {
    namespace po = boost::program_options;

    std::string privateKeyFile;
    std::string publicKeyFile;

    po::options_description general("General options");
    general.add_options()
        ("help", "produce help message")
        ("generate-rsa,g",
            "generate RSA keys and save to public.key and private.key")
        ("publickey",
            po::value<std::string>(&publicKeyFile)
                ->default_value("public.key"),
            "path to publickey (default \"public.key\"")
        ("privatekey",
            po::value<std::string>(&privateKeyFile)
                ->default_value("private.key"),
            "path to private key (default \"private.key\"");

    po::options_description openContainer("Open existing container");
    openContainer.add_options()
        ("open,o", po::value<std::string>(), "open existing container")
        ("unpack,u", po::value<std::string>(),
            "unpack selected files to directory")
        ("unpackAll,U", po::value<std::string>(),
            "unpack all files to directory")
        ("add,a", "add selected files");

    po::options_description createContainer("Create new container");
    createContainer.add_options()
        ("create,c", po::value<std::string>(), "create new container");

    po::options_description hidden("Hidden options");
    hidden.add_options()
        ("input-file", po::value<std::vector<std::string>>(),
            "input container file");


    po::options_description cmdlineOptions;
    cmdlineOptions
        .add(general)
        .add(openContainer)
        .add(createContainer)
        .add(hidden);

    po::positional_options_description p;
    p.add("input-file", -1);

    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).
        options(cmdlineOptions).positional(p).run(), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout
            << "Usage: CryptoContainer [options] <input or output files>"
            << std::endl;
        std::cout << general << "\n";
        std::cout << openContainer << "\n";
        std::cout << createContainer << "\n";
        return 1;
    }

    if (vm.count("generate-rsa")) {
        std::cout << "Generating RSA keys" << std::endl;
        auto RSAKeys = cc::generateRSAKeys();

        // Save public key
        std::cout << "Public key... ";
        cc::saveKeyToFile<CryptoPP::RSA::PublicKey>("public.key",
                                                     RSAKeys.second);
        std::cout << "OK" << std::endl;

        // Save private key
        std::cout << "Private key... ";
        cc::saveKeyToFile<CryptoPP::RSA::PrivateKey>("private.key",
                                                     RSAKeys.first);
        std::cout << "OK" << std::endl;

        return 1;
    }

    if (vm.count("create")) {
        std::cout << "Create container" << std::endl;

        if (!vm.count("input-file")) {
            std::cout << "Error: Need select input files" << std::endl;
            return -1;
        }

        if (!boost::filesystem::exists(publicKeyFile)) {
            std::cout << "Error: Public key doesn't exists" << std::endl;
            return -1;
        }

        if (boost::filesystem::is_directory(vm["create"].as<std::string>())) {
            std::cout << "Error: Path direct to directory" << std::endl;
            return -1;
        }

        auto publicKey =
            cc::loadKeyFromFile<CryptoPP::RSA::PublicKey>(publicKeyFile);

        auto container =
            cc::Container::openNewContainer(vm["create"].as<std::string>(),
                                            publicKey);

        if (!container) {
            std::cout << "invalid key or can't open file" << std::endl;
            return -1;
        }

        const auto pathsToPack =
            vm["input-file"].as<std::vector<std::string>>();
        for (auto &input : pathsToPack) {
            container->addFileOrFolder(input);
        }

        std::cout << "Wait a while..." << std::endl;
        container->save();
        std::cout << "Created " << vm["create"].as<std::string>()
            << " container" << std::endl;

        return 0;
    }

    if (vm.count("open")) {
        std::cout << "Open existed container" << std::endl;

        if (!boost::filesystem::exists(publicKeyFile)) {
            std::cout << "Error: Public key doesn't exists" << std::endl;
            return -1;
        }

        if (!boost::filesystem::exists(privateKeyFile)) {
            std::cout << "Error: Private key doesn't exists" << std::endl;
            return -1;
        }

        auto privateKey =
            cc::loadKeyFromFile<CryptoPP::RSA::PrivateKey>(privateKeyFile);

        auto publicKey =
            cc::loadKeyFromFile<CryptoPP::RSA::PublicKey>(publicKeyFile);

        auto container = cc::Container::openExistedContainer(
            vm["open"].as<std::string>(), publicKey, privateKey);

        if (!container) {
            std::cout << "Can't open container" << std::endl;
            return -1;
        }

        std::cout << "Wait a while..." << std::endl;

        if (vm.count("unpackAll")) {
            const std::string path = vm["unpackAll"].as<std::string>();
            container->unpackAll(path);
            std::cout << "Unpacked all data to: " << path << std::endl;
            return 0;
        } else if (vm.count("unpack")) {
            const std::string targetPath = vm["unpack"].as<std::string>();

            const auto pathsToUnpack =
                vm["input-file"].as<std::vector<std::string>>();

            for (auto& path : pathsToUnpack) {
                std::cout << "Unpack: " << path << std::endl;
                container->unpack(path, targetPath);
            }

            std::cout << "Unpacked all data to: " << targetPath << std::endl;

            return 0;
        } else if (vm.count("add")) {
            const auto pathsToPack =
                vm["input-file"].as<std::vector<std::string>>();

            for (auto &input : pathsToPack) {
                container->addFileOrFolder(input);
            }

            container->save();
            std::cout << "Added" << std::endl;
        } else {
            std::cout << "Invalid command!" << std::endl;
        }
    }

    return 0;
}
