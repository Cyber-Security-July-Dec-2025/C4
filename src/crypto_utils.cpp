// src/crypto_utils.cpp
#include "crypto_utils.h"

// Crypto++ headers — bare names because your headers are in /Users/pritesh/cryptopp
#include <files.h>
#include <osrng.h>
#include <rsa.h>
#include <oaep.h>
#include <sha.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <secblock.h>

#include <iostream>
#include <fstream>

using namespace CryptoPP;
using namespace std;

bool CryptoUtils::LoadPublicKey(const std::string& filename, RSA::PublicKey &pub) {
    try {
        FileSource fs(filename.c_str(), true /*pumpAll*/);
        pub.BERDecode(fs);
        return true;
    } catch(const Exception& e) {
        cerr << "LoadPublicKey error: " << e.what() << endl;
        return false;
    }
}

bool CryptoUtils::LoadPrivateKey(const std::string& filename, RSA::PrivateKey &priv) {
    try {
        FileSource fs(filename.c_str(), true /*pumpAll*/);
        priv.BERDecode(fs);
        return true;
    } catch(const Exception& e) {
        cerr << "LoadPrivateKey error: " << e.what() << endl;
        return false;
    }
}

bool CryptoUtils::RSAEncrypt(const RSA::PublicKey &pub, const std::vector<uint8_t> &plain, std::vector<uint8_t> &cipher) {
    try {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(pub);
        SecByteBlock out(e.CiphertextLength(plain.size()));
        e.Encrypt(rng, plain.data(), plain.size(), out);
        cipher.assign(out.begin(), out.end());
        return true;
    } catch(const Exception& e) {
        cerr << "RSAEncrypt error: " << e.what() << endl;
        return false;
    }
}

bool CryptoUtils::RSADecrypt(const RSA::PrivateKey &priv, const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain) {
    try {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor d(priv);
        SecByteBlock out(d.MaxPlaintextLength(cipher.size()));
        DecodingResult result = d.Decrypt(rng, cipher.data(), cipher.size(), out);
        if(!result.isValidCoding) {
            cerr << "RSADecrypt: invalid coding" << endl;
            return false;
        }
        plain.assign(out.begin(), out.begin() + result.messageLength);
        return true;
    } catch(const Exception& e) {
        cerr << "RSADecrypt error: " << e.what() << endl;
        return false;
    }
}

bool CryptoUtils::AESEncrypt(const std::vector<uint8_t> &key, const std::string &plain, std::vector<uint8_t> &iv, std::vector<uint8_t> &cipher) {
    try {
        AutoSeededRandomPool rng;
        iv.resize(AES::BLOCKSIZE);
        rng.GenerateBlock(iv.data(), iv.size());

        CBC_Mode< AES >::Encryption enc;
        SecByteBlock keyBlock(key.data(), key.size());
        enc.SetKeyWithIV(keyBlock, key.size(), iv.data());

        std::string cipherText;
        StringSource ss(plain, true,
            new StreamTransformationFilter(enc,
                new StringSink(cipherText)
            )
        );

        cipher.assign(cipherText.begin(), cipherText.end());
        return true;
    } catch(const Exception& e) {
        cerr << "AESEncrypt error: " << e.what() << endl;
        return false;
    }
}

bool CryptoUtils::AESDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &cipher, std::string &plain) {
    try {
        CBC_Mode< AES >::Decryption dec;
        SecByteBlock keyBlock(key.data(), key.size());
        dec.SetKeyWithIV(keyBlock, key.size(), iv.data());

        std::string recovered;
        StringSource ss(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec,
                new StringSink(recovered)
            )
        );
        plain = recovered;
        return true;
    } catch(const Exception& e) {
        cerr << "AESDecrypt error: " << e.what() << endl;
        return false;
    }
}
