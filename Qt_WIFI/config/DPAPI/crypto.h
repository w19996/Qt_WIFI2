#pragma once

#include<string>
#include<map>
#include<vector>
#include<windows.h>
#include<algorithm>
#include<QString>
#include<QByteArray>
#include<QUuid>
#include<QDebug>
#include"AlgoInfo.h"
extern "C" {
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha512.h"
}


QUuid uuidFromLittleEndian(const QByteArray& data);
struct key_type
{
    uint32_t type;
    std::vector<uint8_t> key;
};
extern std::map<int, Algoinfo>* AlgorithmInfo;

//class algo_decrypt
//{
//public:
//    algo_decrypt(int cipherAlgo_ivlen, int cipherAlgo_keylen,int hashAlgo_keylen, const std::vector<unsigned char>& raw, const std::vector<unsigned char>& encKey, const std::vector<unsigned char>& iv, int rounds,std::string hname)
//        :cipherAlgo_ivlen(cipherAlgo_ivlen)
//        , cipherAlgo_keylen(cipherAlgo_keylen)
//        , hashAlgo_keylen(hashAlgo_keylen)
//        , raw(raw)
//        , encKey(encKey)
//        , iv(iv)
//        , rounds(rounds)
//        , hname(hname)
//    {}
//    QByteArray pbkdf2(const QByteArray& password, const QByteArray& salt, int iterations, int keyLen, std::string hname);
//    std::vector<unsigned char> cipher();
//
//private:
//    const mbedtls_cipher_info_t* info_from_cipherAlgo(std::string hname, std::string moudle);
//    //ALG_ID cipherAlgo;
//    int cipherAlgo_ivlen;
//    int cipherAlgo_keylen;
//    int hashAlgo_keylen;
//    const std::vector<unsigned char>& raw;
//    const std::vector<unsigned char>& encKey;
//    const std::vector<unsigned char>& iv;
//    int rounds;
//    QByteArray derived;
//    QByteArray key;
//    QByteArray iv2;
//    std::string hname;
//    std::vector<unsigned char> output;
//};
std::vector<unsigned char> dataDecrypt(ALG_ID cipherAlgo, ALG_ID hashAlgo, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& pwdhash, const std::vector<unsigned char>& iv, int rounds);

std::vector<unsigned char> DPAPIHmac(ALG_ID hashAlgo, const std::vector<unsigned char> & pwdhash, const std::vector<unsigned char> & hmacSalt, const std::vector<unsigned char> & value);

std::vector<uint8_t> derivePwdHash(const std::vector<unsigned char>& pwdhash, const std::string& sid, const std::string& digest = "SHA1");

std::pair<std::string, std::map<std::string, key_type>> decrypt_lsa_key_nt6(const std::vector<unsigned char>& lsakey, const std::vector<unsigned char>& syskey);
std::vector<uint8_t> decrypt_lsa_secret(const std::vector<unsigned char>& secret, std::map<std::string, key_type>& lsa_keys);
std::vector<uint8_t> CryptSessionKeyXP(const std::vector<uint8_t>& masterkey, const std::vector<uint8_t>& nonce, ALG_ID hashAlgo, const std::vector<uint8_t>* entropy = nullptr, const std::vector<uint8_t>* strongPassword = nullptr, const std::vector<uint8_t>* verifBlob = nullptr);

std::vector<uint8_t> CryptSessionKeyWin7(const std::vector<uint8_t>& masterkey, const std::vector<uint8_t>& nonce, ALG_ID hashAlgo, const std::vector<uint8_t>* entropy = nullptr, const std::vector<uint8_t>* strongPassword = nullptr, const std::vector<uint8_t>* verifBlob = nullptr);

std::vector<uint8_t> CryptDeriveKey(std::vector<uint8_t> h, ALG_ID cipherAlgo, ALG_ID hashAlgo);