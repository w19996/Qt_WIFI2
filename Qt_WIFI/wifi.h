#pragma once

#include<string>
#include<vector>
#include<map>
#include<QDirIterator>
#include<QXmlStreamReader>
#include<QFileDialog>
#include<QMessageBox>
#include"utils.h"
#include"config/dpapi.h"

class wifi:public QObject
{
    Q_OBJECT
public:
    void run(std::string software_name = "");
    //bool system_module;
    //std::string name;
    //std::string category;
    void doWork();
    std::vector<QMap<QString, QString>> pwdFound;
    void saveFile();
signals:
    void add_table(QString SSID,QString xmlPath,QString password);
};


