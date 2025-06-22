#pragma once
#include<string>
#include<functional>
#include<QUuid>
#include"config/DPAPI/structures.h"
#include"config/DPAPI/crypto.h"
#include"config/DPAPI/masterkey.h"
extern "C" {
#include "mbedtls/cipher.h"
}
extern std::map<int, Algoinfo>* AlgorithmInfo;
class DPAPIBlob
{
public:
	DPAPIBlob(const QByteArray& dpapiblob) :dpapiblob(dpapiblob) {}
	bool decrypt(const std::vector<uint8_t>& masterkey, std::vector<uint8_t>* entropy = nullptr, std::vector<uint8_t>* strongPassword = nullptr);
	std::tuple<bool, std::optional<QString>> decrypt_encrypted_blob(MasterKeyPool* mkp, std::string entropy_hex = "");
	DPAPI_BLOB_t dpapiblob;
	bool decrypted = false;
	QString cleartext;
};

