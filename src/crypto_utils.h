#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>
#include <cstdint>          // for uint8_t

// Crypto++ headers — bare names because your headers are directly under /Users/pritesh/cryptopp
#include <rsa.h>
#include <secblock.h>
#include <osrng.h>
#include <files.h>
#include <oaep.h>
#include <sha.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using std::string;
using std::vector;
using uint8_t = std::uint8_t;
using CryptoPP::RSA;

class CryptoUtils {
public:
    static bool LoadPublicKey(const std::string& filename, RSA::PublicKey &pub);
    static bool LoadPrivateKey(const std::string& filename, RSA::PrivateKey &priv);

    // RSA OAEP encrypt/decrypt for session key
    static bool RSAEncrypt(const RSA::PublicKey &pub, const std::vector<uint8_t> &plain, std::vector<uint8_t> &cipher);
    static bool RSADecrypt(const RSA::PrivateKey &priv, const std::vector<uint8_t> &cipher, std::vector<uint8_t> &plain);

    // AES-CBC encryption (key size 16/24/32 bytes). Returns iv and ciphertext.
    static bool AESEncrypt(const std::vector<uint8_t> &key, const std::string &plain, std::vector<uint8_t> &iv, std::vector<uint8_t> &cipher);
    static bool AESDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &cipher, std::string &plain);
};

#endif // CRYPTO_UTILS_H
