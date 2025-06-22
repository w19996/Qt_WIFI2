#include"dpapi.h"
#include<QDebug>
Decrypt_DPAPI::Decrypt_DPAPI(std::string password,std::vector<unsigned char> pwdhash)
{
    std::string adding_missing_path = u8"";
    std::string path = build_path("DPAPI");
    qDebug() << "DPAPI：" << path;
    if (constant::dump == "local")
        adding_missing_path = u8"/Microsoft";
    QDir dir(QString::fromStdString(path));
    if (dir.exists())
    {
        qDebug() << dir << "exists";
        std::string protect_folder = path + u8"Roaming{path}/Protect";
        protect_folder = format_path(protect_folder, "\\{path\\}", adding_missing_path);
        //qDebug()<<protect_folder;
        std::string credhist_file = path + u8"Roaming{path}/Protect/CREDHIST";
        credhist_file = format_path(credhist_file, "\\{path\\}", adding_missing_path);
        //qDebug()<<credhist_file;
        dir.setPath(QString::fromStdString(protect_folder));
        if (dir.exists())
        {
            qDebug() << "protect_folder：" << protect_folder;
            QFileInfoList entries = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
            //qDebug()<<entries;
            for (const auto& path : entries)
            {
                if (path.fileName().left(2) == "S-")
                {
                    this->sid = path.fileName().toStdString();
                    qDebug() << this->sid;
                    break;
                }
            }
            if (!this->sid.empty())
            {
                std::string masterkeydir = protect_folder + "/" + this->sid;
                dir.setPath(QString::fromStdString(masterkeydir));
                if (dir.exists())
                {
                    qDebug() << "masterkeydir：" << masterkeydir;
                    this->umkp = new MasterKeyPool;
                    this->umkp->load_directory(masterkeydir);
                    qDebug() << "++++++++++++++++++++++++++++++++++++++++++++++";
                    //this->umkp->add_credhist_file(this->sid, credhist_file);
                    if (!password.empty())
                    {
                        //this->umkp->try_credential(sid = self.sid, password = password);
                    }
                    else if(!pwdhash.empty())
                    {
                        //this->umkp->try_credential_hash();//一般不执行
                    }
                }
            }
        }
    }
    path = build_path("Hives");
    dir.setPath(QString::fromStdString(path));
    if (dir.exists())
    {
        std::string system = path + "/SYSTEM";
        qDebug() << "system："<< system;
        std::string security = path + "/SECURITY";
        qDebug() << "security："<< security;
        QFileInfo systemInfo(QString::fromStdString(system));
        QFileInfo securityInfo(QString::fromStdString(security));
        if (systemInfo.exists() && securityInfo.exists())
        {
            if (systemInfo.isFile() && securityInfo.isFile())
            {
                Regedit reg;
                qDebug() << "reg创建成功";
                auto secrets = reg.get_lsa_secrets(security, system);
                if (!(secrets.empty()))
                {
                    std::vector<uint8_t> dpapi_system;
                    auto it = secrets.find(QString("DPAPI_SYSTEM"));
                    if (it != secrets.end())
                    {
                        const auto& innerMap = it->second;
                        auto innerIt = innerMap.find(QString(L"CurrVal"));
                        if (innerIt != innerMap.end())
                        {
                            dpapi_system = innerIt->second;
                            qDebug() << "dpapi_system：" << dpapi_system;
                        }
                    }
                    std::string path = build_path("Dpapi_System");
                    qDebug() << path;

                    dir.setPath(QString::fromStdString(path));
                    qDebug() << dir;
                    if (dir.exists())
                    {
                        std::string masterkeydir = path + "/Protect/S-1-5-18/User";
                        dir.setPath(QString::fromStdString(masterkeydir));
                        qDebug() << dir;
                        if (dir.exists())
                        {
                            qDebug() << dir << "\n";
                            this->smkp = new MasterKeyPool;
                            this->smkp->load_directory(masterkeydir);
                            qDebug() << "smkp->load_directory";
                            this->smkp->add_system_credential(dpapi_system);
                            qDebug() << "smkp->add_system_credential";
                            this->smkp->try_system_credential();
                            qDebug() << "smkp->try_system_credential";
                        }
                    }
                }
            }
        }
    }
}

QString Decrypt_DPAPI::decrypt_wifi_blob(const std::string& key_material)const
{
    qDebug()  << this->smkp;
    if (this->smkp)
    {
        qDebug() << "Decrypt_DPAPI::smkp" << this->smkp << "\n";
        QByteArray hexStr = QByteArray::fromStdString(key_material);
        QByteArray bytes = QByteArray::fromHex(hexStr);
        qDebug() << bytes.toHex();
        DPAPIBlob blob(bytes);
        auto msg = blob.decrypt_encrypted_blob(this->smkp);
        qDebug() << "msg：" << std::get<1>(msg).value() << "\n";
        return std::get<1>(msg).value();
    }
    return "";
}


Decrypt_DPAPI::~Decrypt_DPAPI()
{
    delete umkp;
    delete smkp;
}
