#pragma once

#include<QDir>
#include<QDir>
#include<QFileInfo>
#include<QFileInfoList>
#include<QStringList>
#include"utils.h"
#include"config/DPAPI/masterkey.h"
#include"registry.h"
#include"blob.h"

class Decrypt_DPAPI
{
public:
    Decrypt_DPAPI(std::string password = "", std::vector<unsigned char> pwdhash = {});
    QString decrypt_wifi_blob(const std::string& key_material)const;
    ~Decrypt_DPAPI();
    std::string sid;
    MasterKeyPool* umkp = nullptr;
    MasterKeyPool* smkp = nullptr;

};


