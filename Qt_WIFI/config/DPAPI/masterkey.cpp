#include "masterkey.h"
#include<QDebug>

MasterKey::MasterKey(PMASTERKEY mk)
{
    this->mk = mk;
}
void MasterKey::decrypt_with_hash(std::string sid, const std::vector<unsigned char>& pwdhash)
{
    this->decrypt_with_key(pwdhash);
}


void MasterKey::decrypt_with_key(const std::vector<unsigned char>& pwdhash)
{
    if (this->decrypted || !(this->mk->ciphertextlen))
        return;
    //std::vector<unsigned char> pw(std::begin(this->mk->ciphertext), std::end(this->mk->ciphertext));
    std::vector<unsigned char> ciphertext(this->mk->ciphertext, this->mk->ciphertext + this->mk->ciphertextlen);
    std::vector<unsigned char> iv(std::begin(this->mk->iv), std::end(this->mk->iv));
    std::vector<unsigned char> cleartxt(dataDecrypt(this->mk->cipherAlgo, this->mk->hashAlgo, ciphertext, pwdhash, iv, this->mk->rounds));
    
    this->key.assign(cleartxt.end() - 64, cleartxt.end());
    std::vector<unsigned char> hmacSalt(cleartxt.begin(), cleartxt.begin() + 16);
    std::vector<unsigned char> hmac(cleartxt.begin() + 16, cleartxt.begin() + 16 + (*AlgorithmInfo)[this->mk->hashAlgo].digestLength);
    qDebug() << hmac;

    std::vector<unsigned char> hmacComputed(DPAPIHmac(this->mk->hashAlgo, pwdhash, hmacSalt, this->key));
    qDebug() << hmacComputed;

    this->decrypted = (hmac == hmacComputed);
    qDebug() << this->decrypted;

    if (decrypted)
    {
        this->key_hash.resize(20);
        mbedtls_sha1(this->key.data(), this->key.size(), this->key_hash.data());
    }
}

std::vector<unsigned char> MasterKeyFile::get_key()
{
    if (this->mk.decrypted)
    {
        if (!this->mk.key.empty())
            return this->mk.key;
        else
            return this->mk.key_hash;
    }
    else if(this->bk.decrypted)
    {
        return this->mk.key;
    }
    return this->mk.key;
}


void MasterKeyPool::add_master_key(std::string mkey)
{
    //MasterKeyFile mkfile(mkey);
    MKPtr mkfile = std::make_shared<MasterKeyFile>(mkey);
    QString guidStr = QString::fromWCharArray(mkfile->mkf._MasterKeys->Guid);
    qDebug() << guidStr.toStdString();
    this->keys[guidStr.toStdString()].keys.push_back(mkfile);
    qDebug() << this->keys[guidStr.toStdString()].keys.size();
    this->mkfiles.push_back(mkfile);
}

bool MasterKeyPool::load_directory(const std::string& directoryPath) {
    QDir dir(QString::fromStdString(directoryPath));
    if (!dir.exists())
        return false;

    qDebug() << dir;
    QStringList files = dir.entryList(QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);
    qDebug() << files;

    for (const QString& fileName : files)
    {
        if (fileName != "Preferred")
        {
            QString fullPath = dir.absoluteFilePath(fileName);
            qDebug() << fullPath;

            this->add_master_key(fullPath.toStdString());
            this->nb_mkf++;

        }
        
        
    }
    return true;
}

//void MasterKeyPool::get_master_keys(const std::string& guid)
//{
//
//}
std::optional<std::vector<MKPtr>> MasterKeyPool::get_master_keys(const std::string& guid) const
{
    qDebug() << guid;
     auto it = this->keys.find(guid);
        if (it != this->keys.end())
        {
            return it->second.keys;
        }
        else
        {
            return std::nullopt;
        }
}

std::optional<std::string> MasterKeyPool::get_password(const std::string& guid) const {
    auto it = keys.find(guid);
    if (it != keys.end()) {
        return it->second.password;
    }
    else {
        return std::nullopt;
    }
}


std::optional<std::string> MasterKeyPool::get_preferred_guid()
{
    if (!this->preferred_guid.empty())
        return this->preferred_guid;

    if (this->mk_dir != "")
    {
        QString preferredPath = QString::fromUtf8(this->mk_dir) + "/Preferred";

        QFile file(preferredPath);
        if (!file.open(QIODevice::ReadOnly))
            return std::nullopt;

        QByteArray guidBytes = file.read(16);  // GUID 是 16 字节
        file.close();

        if (guidBytes.size() != 16)
            return std::nullopt;

        // 从16字节数据构建QUuid（与Windows GUID格式兼容）
        QUuid uuid = QUuid::fromRfc4122(guidBytes);

        this->preferred_guid = uuid.toString(QUuid::WithoutBraces).toUpper().toUtf8().constData(); 
        //return preferredGuid;
    }

    return std::nullopt;
}

std::optional<std::string> MasterKeyPool::get_cleartext_password(std::string guid )
{
    if (guid == "")
        guid = this->get_preferred_guid().value();
    else
        return this->get_password(guid);
}

void MasterKeyPool::add_system_credential(const std::vector<unsigned char>& blob)
{
    system.CreatCredSystem(blob);
}

void MasterKeyPool::try_system_credential()
{
    for (auto& mkfile : this->mkfiles)
    {
        if (!mkfile->decrypted)
        {
            qDebug() << "system.user";
            mkfile->mk.decrypt_with_key(this->system.user);
            if (!mkfile->mk.decrypted)
            {
                qDebug() << "system.machine";
                mkfile->mk.decrypt_with_key(this->system.machine);
            }
            if (mkfile->mk.decrypted)
            {
                mkfile->decrypted = true;
                nb_mkf_decrypted++;
                //results.emplace_back("[+] System masterkey decrypted for " + mkfile.mk.guid);
            }
            /*else {
                results.emplace_back("[-] System masterkey not decrypted for masterkey " + mkfile.mk.guid);
            }*/
        }
        //qDebug() << 11111;
        //qDebug() << mkfile.decrypted ;
    }
    
}

void MasterKeyPool::add_credhist_file(std::string sid, std::string credfile)
{
    try
    {
        this->credhists[sid] = CredHistFile(credfile); // 构造并插入
    }
    catch (...)
    {
    }
}

