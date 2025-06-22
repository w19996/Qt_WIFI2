#include "structures.h"


MASTERKEY::~MASTERKEY()
{
    //delete[] this->ciphertext;
}
MASTERKEY_DOMAINKEY::~MASTERKEY_DOMAINKEY()
{
    //delete[] this->pbAccesscheck;
    //delete[] this->pbSecret;
}
MASTERKEYS::~MASTERKEYS()
{
    //delete this->MasterKey;
    //delete this->BackupKey;
    //delete this->DomainKey;
    //delete this->CredHist;
}
MKFile::MKFile(const std::string& path)
{
    //std::vector<BYTE> _binFile;
    QFile file(QString::fromStdString(path));
    if (!file.open(QIODevice::ReadOnly))
    {
        qWarning() << "Failed to open file:" << path;
        return;
    }

    QByteArray _binFile = file.readAll();  // 读取所有二进制数据
    file.close();
    _MasterKeys = new MASTERKEYS;
    memcpy(_MasterKeys, _binFile.constData(), FIELD_OFFSET(MASTERKEYS, MasterKey));
    if (_MasterKeys->MasterKeyLen)
    {
        _MasterKeys->MasterKey = new MASTERKEY;  // FIELD_OFFSET(MASTERKEYS, MasterKey));
        memcpy(_MasterKeys->MasterKey, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey), FIELD_OFFSET(MASTERKEY, ciphertext));
        _MasterKeys->MasterKey->ciphertextlen = _MasterKeys->MasterKeyLen - FIELD_OFFSET(MASTERKEY, ciphertext);
        _MasterKeys->MasterKey->ciphertext = new BYTE[_MasterKeys->MasterKey->ciphertextlen];
        memcpy(_MasterKeys->MasterKey->ciphertext, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + FIELD_OFFSET(MASTERKEY, ciphertext), _MasterKeys->MasterKey->ciphertextlen);   //(PBYTE)((PBYTE)_binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + FIELD_OFFSET(MASTERKEY, ciphertext));
    }

    if (_MasterKeys->BackupKeyLen)
    {
        _MasterKeys->BackupKey = new MASTERKEY;
        memcpy(_MasterKeys->BackupKey, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen, FIELD_OFFSET(MASTERKEY, ciphertext));
        _MasterKeys->BackupKey->ciphertextlen = _MasterKeys->BackupKeyLen - FIELD_OFFSET(MASTERKEY, ciphertext);
        _MasterKeys->BackupKey->ciphertext = new BYTE[_MasterKeys->BackupKey->ciphertextlen];
        memcpy(_MasterKeys->BackupKey->ciphertext, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen + FIELD_OFFSET(MASTERKEY, ciphertext), _MasterKeys->BackupKey->ciphertextlen);
    }
    if (_MasterKeys->CredHistLen)
    {
        _MasterKeys->CredHist = new MASTERKEY_CREDHIST;
        memcpy(_MasterKeys->CredHist, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen + _MasterKeys->BackupKeyLen, _MasterKeys->CredHistLen);
    }
    if (_MasterKeys->DomainKeyLen)
    {
        _MasterKeys->DomainKey = new MASTERKEY_DOMAINKEY;
        memcpy(_MasterKeys->DomainKey, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen + _MasterKeys->BackupKeyLen + _MasterKeys->CredHistLen, FIELD_OFFSET(MASTERKEY_DOMAINKEY, pbSecret));
        _MasterKeys->DomainKey->pbSecret = new BYTE[_MasterKeys->DomainKey->SecretLen];
        memcpy(_MasterKeys->DomainKey->pbSecret, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen + _MasterKeys->BackupKeyLen + _MasterKeys->CredHistLen + FIELD_OFFSET(MASTERKEY_DOMAINKEY, pbSecret), _MasterKeys->DomainKey->SecretLen);
        _MasterKeys->DomainKey->pbAccesscheck = new BYTE[_MasterKeys->DomainKey->AccesscheckLen];
        memcpy(_MasterKeys->DomainKey->pbAccesscheck, _binFile.constData() + FIELD_OFFSET(MASTERKEYS, MasterKey) + _MasterKeys->MasterKeyLen + _MasterKeys->BackupKeyLen + _MasterKeys->CredHistLen + FIELD_OFFSET(MASTERKEY_DOMAINKEY, pbSecret) + _MasterKeys->DomainKey->SecretLen, _MasterKeys->DomainKey->AccesscheckLen);
    }
}
MKFile::~MKFile()
{
    //delete _MasterKeys;
}

void CRED_HIST_FILE::CREAT_CRED_HIST_FILE(const std::string& path)
{
    QFile file(QString::fromStdString(path));
    file.open(QIODevice::ReadOnly);
    QByteArray binFile = file.readAll();
    cred_hist_file = new CRED_HIST_FILE_HEADER;
    std::memcpy(cred_hist_file, binFile.constData(), offsetof(CRED_HIST_FILE_HEADER, cred_hist));
    if (binFile.size() > offsetof(CRED_HIST_FILE_HEADER, cred_hist))
    {
        size_t setof_cred_hist = offsetof(CRED_HIST_FILE_HEADER, cred_hist);
        this->cred_hist_file->cred_hist = new CRED_HIST;
        std::memcpy(this->cred_hist_file->cred_hist, binFile.constData() + setof_cred_hist, offsetof(CRED_HIST, SID));
        size_t setof_SID = setof_cred_hist + offsetof(CRED_HIST, SID);
        this->cred_hist_file->cred_hist->SID = new RPC_SID;
        std::memcpy(this->cred_hist_file->cred_hist->SID, binFile.constData() + setof_cred_hist, offsetof(RPC_SID, subAuth));
        size_t setof_subAuth = setof_SID + offsetof(RPC_SID, subAuth);
        size_t subAuth_size = this->cred_hist_file->cred_hist->SID->length;
        this->cred_hist_file->cred_hist->SID->subAuth.resize(subAuth_size);
        std::memcpy(this->cred_hist_file->cred_hist->SID->subAuth.data(), binFile.constData() + setof_subAuth, subAuth_size);
        size_t setof_encrypted = subAuth_size + subAuth_size;
        size_t total_len = this->cred_hist_file->cred_hist->shaHashLen + this->cred_hist_file->cred_hist->ntHashLen;
        size_t encrypted_len = total_len + total_len % 16;
        this->cred_hist_file->cred_hist->encrypted.resize(encrypted_len);
        std::memcpy(this->cred_hist_file->cred_hist->encrypted.data(), binFile.constData() + setof_encrypted, encrypted_len);
        size_t offset_revision2 = setof_encrypted + encrypted_len;
        std::memcpy(&(this->cred_hist_file->cred_hist->revision), binFile.constData() + offset_revision2, sizeof(uint32_t) + sizeof(GUID));

    }

}

DPAPI_BLOB_t::DPAPI_BLOB_t(const QByteArray& dpapiblob)
{
    const uint8_t* _keyMaterialBinary = (uint8_t*)dpapiblob.constData();
    this->_keyMaterial = new DPAPI_BLOB;
    memcpy(_keyMaterial, _keyMaterialBinary, FIELD_OFFSET(DPAPI_BLOB, szDescription));

    _keyMaterial->szDescription = new WCHAR[_keyMaterial->dwDescriptionLen];
    memcpy(_keyMaterial->szDescription, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription), _keyMaterial->dwDescriptionLen);
    memcpy(&(_keyMaterial->algCrypt), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen, sizeof(ALG_ID));
    memcpy(&(_keyMaterial->dwAlgCryptLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID), sizeof(DWORD));
    memcpy(&(_keyMaterial->dwSaltLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD), sizeof(DWORD));

    _keyMaterial->pbSalt = new BYTE[_keyMaterial->dwSaltLen];
    memcpy(_keyMaterial->pbSalt, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD), _keyMaterial->dwSaltLen);

    memcpy(&(_keyMaterial->dwHmacKeyLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen, sizeof(DWORD));

    _keyMaterial->pbHmackKey = new BYTE[_keyMaterial->dwHmacKeyLen];
    memcpy(_keyMaterial->pbHmackKey, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD), _keyMaterial->dwHmacKeyLen);
    memcpy(&(_keyMaterial->algHash), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen, sizeof(ALG_ID));
    memcpy(&(_keyMaterial->dwAlgHashLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID), sizeof(DWORD));
    memcpy(&(_keyMaterial->dwHmac2KeyLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD), sizeof(DWORD));

    _keyMaterial->pbHmack2Key = new BYTE[_keyMaterial->dwHmac2KeyLen];
    memcpy(_keyMaterial->pbHmack2Key, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD), _keyMaterial->dwHmac2KeyLen);
    memcpy(&(_keyMaterial->dwDataLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwHmac2KeyLen, sizeof(DWORD));

    _keyMaterial->pbData = new BYTE[_keyMaterial->dwDataLen];
    memcpy(_keyMaterial->pbData, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwHmac2KeyLen + sizeof(DWORD), _keyMaterial->dwDataLen);
    memcpy(&(_keyMaterial->dwSignLen), _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwHmac2KeyLen + sizeof(DWORD) + _keyMaterial->dwDataLen, sizeof(DWORD));

    _keyMaterial->pbSign = new BYTE[_keyMaterial->dwSignLen];
    memcpy(_keyMaterial->pbSign, _keyMaterialBinary + FIELD_OFFSET(DPAPI_BLOB, szDescription) + _keyMaterial->dwDescriptionLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwSaltLen + sizeof(DWORD) + _keyMaterial->dwHmacKeyLen + sizeof(ALG_ID) + sizeof(DWORD) + sizeof(DWORD) + _keyMaterial->dwHmac2KeyLen + sizeof(DWORD) + _keyMaterial->dwDataLen + sizeof(DWORD), _keyMaterial->dwSignLen);
    
    int blob_begin = sizeof(this->_keyMaterial->dwVersion) + sizeof(this->_keyMaterial->guidProvider);
    int blob_len = dpapiblob.size() - blob_begin - this->_keyMaterial->dwSignLen;

    this->verifBlob.assign(dpapiblob.begin() + blob_begin, dpapiblob.begin() + blob_begin + blob_len);
}