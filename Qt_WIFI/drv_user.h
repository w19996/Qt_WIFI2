#pragma once

#include<string>
#include<vector>
#include<windows.h>
#include <QDir>
#include <QFileInfo>
#include <QFileInfoList>
#include <QStringList>
class Drv
{
public:
    void GetOSPath();
    QFileInfoList m_drives;
};
class User
{
public:
    void GetUser(std::string rootPath);
    QStringList m_userList;
};
//void GetUser(std::string rootPath);

