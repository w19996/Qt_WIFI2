#pragma once

#include<windows.h>
#include<string>
#include<vector>
#include <QFile>
#include <QByteArray>
#include<QDebug>
#include <cstdint>


typedef struct MASTERKEY
{
    DWORD	Version;
    BYTE	iv[16];
    DWORD	rounds;
    ALG_ID	hashAlgo;
    ALG_ID	cipherAlgo;
    PBYTE	ciphertext = nullptr;
    DWORD	ciphertextlen;
    ~MASTERKEY();
}MASTERKEY, * PMASTERKEY;

typedef struct MASTERKEY_CREDHIST
{
    DWORD	Version;
    GUID	guid;
}MASTERKEY_CREDHIST, * PMASTERKEY_CREDHIST;

typedef struct MASTERKEY_DOMAINKEY
{
    DWORD	Version;
    DWORD	SecretLen;
    DWORD	AccesscheckLen;
    GUID	guidMasterKey;
    PBYTE	pbSecret = nullptr;
    PBYTE	pbAccesscheck = nullptr;
    ~MASTERKEY_DOMAINKEY();
}MASTERKEY_DOMAINKEY, * PMASTERKEY_DOMAINKEY;

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
    PMASTERKEY	MasterKey = nullptr;
    PMASTERKEY	BackupKey = nullptr;
    PMASTERKEY_CREDHIST	CredHist = nullptr;
    PMASTERKEY_DOMAINKEY DomainKey = nullptr;

    ~MASTERKEYS();
}MASTERKEYS, * PMASTERKEYS;

class MKFile
{
public:
    MKFile(const std::string& path);
    ~MKFile();

    PMASTERKEYS _MasterKeys = nullptr;
};


#pragma pack(push, 1)
struct CRED_SYSTEM 
{
    uint32_t revision;     // 4 字节小端整数
    char machine[20];      // 20 字节
    char user[20];         // 20 字节
};
struct RPC_SID
{
    uint8_t version;
    uint8_t length;
    uint8_t idAuth;
    std::vector<uint32_t> subAuth;
};
struct CRED_HIST
{
    uint8_t  padding1[4];       // Padding(4)
    uint32_t revision;          // Int32ul
    uint32_t hashAlgo;          // CryptoAlgoAdapter(Int32ul)
    uint32_t rounds;            // Int32ul
    uint8_t  padding2[4];       // Padding(4)
    uint32_t cipherAlgo;        // CryptoAlgoAdapter(Int32ul)
    uint32_t shaHashLen;        // Int32ul
    uint32_t ntHashLen;         // Int32ul
    uint8_t  iv[16];            // Bytes(16)
    RPC_SID* SID = nullptr;               // RPC_SIDAdapter(RPC_SID)
    std::vector<uint8_t> encrypted;
    uint32_t revision2;         // Int32ul
    GUID guid;                  // GuidAdapter(GUID)
};
struct CRED_HIST_FILE_HEADER
{
    uint32_t footmagic;
    GUID guid;
    CRED_HIST* cred_hist = nullptr;
};
class CRED_HIST_FILE
{
public:
    CRED_HIST_FILE() = default;
    void CREAT_CRED_HIST_FILE(const std::string& path);
    CRED_HIST_FILE_HEADER* cred_hist_file = nullptr;
};

struct POL_REVISION
{
    uint16_t minor;
    uint16_t major;
};

typedef struct DPAPI_BLOB
{
    DWORD	dwVersion;
    GUID	guidProvider;
    DWORD	dwMasterKeyVersion;
    GUID	guidMasterKey;
    DWORD	dwFlags;

    DWORD	dwDescriptionLen;
    PWSTR	szDescription;

    ALG_ID	algCrypt;
    DWORD	dwAlgCryptLen;

    DWORD	dwSaltLen;
    PBYTE	pbSalt;

    DWORD	dwHmacKeyLen;
    PBYTE	pbHmackKey;

    ALG_ID	algHash;
    DWORD	dwAlgHashLen;

    DWORD	dwHmac2KeyLen;
    PBYTE	pbHmack2Key;

    DWORD	dwDataLen;
    PBYTE	pbData;

    DWORD	dwSignLen;
    PBYTE	pbSign;
}*PKULL_M_DPAPI_BLOB;
#pragma pack(pop)

class DPAPI_BLOB_t
{
public:
    DPAPI_BLOB_t(const QByteArray& dpapiblob);
    //PBYTE _keyMaterialBinary;
    std::vector<uint8_t> verifBlob;
    PKULL_M_DPAPI_BLOB _keyMaterial;
};

