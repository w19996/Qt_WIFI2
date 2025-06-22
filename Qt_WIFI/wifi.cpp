#include "wifi.h"
#include<QDebug>
void wifi::run(std::string software_name)
{
    std::string path = build_path(software_name);
    qDebug()<<path;
    QDir dir(QString::fromStdString(path));
    if (dir.exists())
    {
        
        Decrypt_DPAPI* dpapi;
        if (constant::user_dpapi)
        {
            qDebug() << "user_dpapi" << constant::user_dpapi;
            dpapi = constant::user_dpapi;
        }
        else
        {
            qDebug() << "new Decrypt_DPAPI";
            dpapi = new Decrypt_DPAPI;
        }
        if (dpapi)
        {
            qDebug() << "dpapi：" << dpapi;
            
            QStringList repositories = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QString& repository : repositories)
            {
                QString wifiDirPath = dir.absoluteFilePath(repository);
                //qDebug() << wifiDirPath;
                QDirIterator it(wifiDirPath, QStringList() << "*.xml", QDir::Files, QDirIterator::Subdirectories);
                while (it.hasNext())
                {
                    QMap<QString, QString> values;
                    QString xmlPath = it.next();
                    qDebug() << xmlPath;
                    QFile file(xmlPath);
                    
                    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
                    {
                        qWarning() << "无法打开文件:" << xmlPath;
                        //return values;
                    }

                    QXmlStreamReader xml(&file);
                    QString currentPath;
                    QString wifiName, authentication, keyMaterial;

                    while (!xml.atEnd() && !xml.hasError()) {
                        xml.readNext();

                        if (xml.isStartElement()) {
                            QString tag = xml.name().toString();
                            //qDebug() << tag<<"\n";

                            currentPath += "/" + tag;

                            if (tag == "name" && currentPath == "/WLANProfile/name")
                            {
                                wifiName = xml.readElementText();
                                //qDebug() << wifiName;
                                currentPath.chop(tag.length() + 1);
                            }
                            else if (tag == "authentication" && currentPath.endsWith("/MSM/security/authEncryption/authentication"))
                            {
                                authentication = xml.readElementText();
                                currentPath.chop(tag.length() + 1);
                            }
                            else if (tag == "keyMaterial" && currentPath.endsWith("/MSM/security/sharedKey/keyMaterial"))
                            {
                                keyMaterial = xml.readElementText();
                                qDebug() << "decrypt_wifi_blob调用";
                                QString password = dpapi->decrypt_wifi_blob(keyMaterial.toStdString());
                                values["password"] = password;
                                qDebug() << "decrypt_wifi_blob";
                                currentPath.chop(tag.length() + 1);
                            }
                        }
                        else if (xml.isEndElement())
                        {
                            QString tag = xml.name().toString();
                            //qDebug() << tag;
                            currentPath.chop(tag.length() + 1);  // remove from path
                        }
                    }

                    if (!wifiName.isEmpty()) values["SSID"] = wifiName;
                    if (!authentication.isEmpty()) values["Authentication"] = authentication;
                    if (!keyMaterial.isEmpty()) values["KeyMaterial"] = keyMaterial;
                    //QString xmlPath_t = xmlPath.replace("/", "\\");
                    //qDebug() << xmlPath_t;
                    values["xmlPath"] = xmlPath;
                    //qDebug() << wifiName << "\t" << authentication << "\t" << keyMaterial<<"\n";
                    if (xml.hasError())
                        qWarning() << "XML解析错误:" << xml.errorString();

                    file.close();
                    this->pwdFound.push_back(values);
                }
            }
            
        }
        
    }
}

void wifi::doWork()
{
	for (auto& info : this->pwdFound)
	{

		emit add_table(info["SSID"], info["xmlPath"], info["password"]);
	}

    //for (int i = 0; i < 5; i++)
    //{
    //    emit add_table("SSID", "C:/config/path", "password");
    //}
	
}


