#pragma once

#include <vector>
#include <map>
#include <string>
#include <string>
#include <Windows.h>
#include "structures.h"
#include "crypto.h"
#include "mbedtls/sha1.h"
#include <QFile>
#include <QByteArray>
#include <QUuid>
#include <QDir>
#include "CredSystem.h"
#include "credhist.h"


/*
typedef struct MASTERKEY
{
    DWORD	Version;
    BYTE	iv[16];
    DWORD	rounds;
    ALG_ID	hashAlgo;
    ALG_ID	cipherAlgo;
    PBYTE	ciphertext;
    DWORD	ciphertextlen;
}MASTERKEY, *PMASTERKEY;

typedef struct MASTERKEY_CREDHIST
{
    DWORD	Version;
    GUID	guid;
}MASTERKEY_CREDHIST, *PMASTERKEY_CREDHIST;

typedef struct MASTERKEY_DOMAINKEY
{
    DWORD	Version;
    DWORD	SecretLen;
    DWORD	AccesscheckLen;
    GUID	guidMasterKey;
    PBYTE	pbSecret;
    PBYTE	pbAccesscheck;
}MASTERKEY_DOMAINKEY, *PMASTERKEY_DOMAINKEY;

typedef struct MASTERKEYS
{
    DWORD	Version;
    DWORD	unk0;
    DWORD	unk1;
    WCHAR	Guid[36];
    DWORD	unk2;
    DWORD	unk3;
    DWORD	Policy;
    DWORD64	MasterKeyLen;
    DWORD64 BackupKeyLen;
    DWORD64 CredHistLen;
    DWORD64	DomainKeyLen;
    PMASTERKEY	MasterKey;
    PMASTERKEY	BackupKey;
    PMASTERKEY_CREDHIST	CredHist;
    PMASTERKEY_DOMAINKEY DomainKey;
}MASTERKEYS, * PMASTERKEYS;
*/
/*
class MasterKeyPool
{
public:
    MasterKeyPool(const std::vector<BYTE>& dpapi_system);
    void try_system_credential(PMASTERKEYS masterkey);
    std::vector<BYTE>* GetKey();
    BOOL GetCryptStatue();

private:
    BOOL decrypt_with_key(PMASTERKEYS masterkey, const std::vector<BYTE>& pwdhash);
    void dataDecrypt(PMASTERKEYS masterkey, const std::vector<BYTE>& pwdhash);
    void pbkdf2(PMASTERKEYS masterkey, DWORD len, const std::vector<BYTE>& pwdhash, ALG_ID hname = CALG_SHA1);
    std::vector<BYTE>* DPAPIHmac(PMASTERKEYS masterkey, const std::vector<BYTE>& pwdhash, std::vector<BYTE>& hmacSalt);
    DWORD _revision;
    std::vector<BYTE> _machine;
    std::vector<BYTE> _user;
    BOOL _decrypted;
    std::vector<BYTE> _buff;
    CryptoAlgo _crypt;
    std::vector<BYTE>* _cleartxt;
    std::vector<BYTE> _KEY;
};
*/
class MasterKey
{
public:
    MasterKey(PMASTERKEY mk);
    void decrypt_with_hash(std::string sid, const std::vector<unsigned char>& pwdhash);
    bool decrypted = false;
    std::vector<unsigned char> key;
    std::vector<unsigned char> key_hash;
    void decrypt_with_key(const std::vector<unsigned char>& pwdhash);
    PMASTERKEY mk;
    
};

class MasterKeyFile
{
public:
    MasterKeyFile(const std::string mkfile)
        :mkf(mkfile)
        , mk(mkf._MasterKeys->MasterKey)
        , bk(mkf._MasterKeys->MasterKey)
        , decrypted(false)
    {}
    std::vector<unsigned char> get_key();
    MKFile mkf;
    bool decrypted;

    MasterKey mk;
    MasterKey bk;
    
};

using MKPtr = std::shared_ptr<MasterKeyFile>;

struct KeyEntry {
    std::optional<std::string> password; // 等价于 None，可以为空
    std::vector<MKPtr> keys;     // 解密的 master keys
};
class MasterKeyPool
{
public:
    void add_master_key(std::string mkeys);
    bool load_directory(const std::string& directoryPath);
    std::optional<std::vector<MKPtr>> get_master_keys(const std::string& guid) const;
    std::optional<std::string> get_preferred_guid();
    std::optional<std::string> get_cleartext_password(std::string guid = "");
    void add_system_credential(const std::vector<unsigned char>& blob);
    void try_system_credential();
    void add_credhist_file(std::string sid, std::string credfile);
//private:
    std::unordered_map<std::string, KeyEntry> keys;
    std::optional<std::string> get_password(const std::string& guid) const;
    std::vector<MKPtr> mkfiles;
    std::map<std::string, CredHistFile> credhists;
    std::string mk_dir = "";
    int nb_mkf = 0;
    int nb_mkf_decrypted = 0;
    std::string preferred_guid;
    CredSystem system;
};


