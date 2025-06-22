#pragma once
#include<vector>
#include<string>
#include<windows.h>
#include<codecvt>
#include<QString>
#include<QUuid>
#include<QStringList>
#include<tchar.h>
#include<tlhelp32.h>
#include<QByteArray>
#include<QThread>
#include"config/DPAPI/crypto.h"
#include"config/DPAPI/structures.h"
#include"log/logger.h"

//class unLoadRegThread :public QThread
//{
//    Q_OBJECT
//public:
//    unLoadRegThread(QString subKey) :subKey(subKey) {}
//protected:
//    void run() override;
//    QString subKey;
//};

//class Privilege
//{
//public:
//    void LoadRegPrivilege(BOOL tag);
//    void FullRegPrivilege(BOOL tag);
//
//    BOOL SetPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege);
//    DWORD GetProcessIdByName(LPCTSTR processName);
//    HANDLE _hProcessToken = NULL;
//    HANDLE _hProcess = NULL;
//    DWORD _dwProcessId = 0;
//};
//
//class Hive
//{
//public:
//    Hive(const QString& header);
//
//    void LoadReg(const QString& path);
//    void unLoadReg();
//    QString subKey;
//
//    
//};


class PrivilegeManager
{
public:
    PrivilegeManager();
    ~PrivilegeManager();
    bool openRegistryKey(const QString& subkey, REGSAM samDesired, HKEY* phKey, HKEY hkey = HKEY_LOCAL_MACHINE);
    bool loadHive(const QString& subKey, const QString& hiveFile);
    bool unloadHive(const QString& subKey);
private:
    bool FullRegPrivilege(BOOL bEnable);
    bool LoadRegPrivilege(BOOL bEnable);
    bool SetPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege);
    DWORD GetProcessIdByName(LPCTSTR processName);
    HANDLE _hProcess;
    HANDLE _hProcessToken;
};

class Regedit
{
public:
    
    ~Regedit();
	QByteArray get_syskey(const std::string& system);
    std::vector<uint8_t> get_lsa_key(const std::string& security);
    std::map<QString, std::map<QString, std::vector<uint8_t>>> get_lsa_secrets(std::string security, std::string system);

	std::vector<uint8_t> syskey;
    std::map<std::string, key_type> lsakeys;
	double policy = 0;

    //Privilege* p;
};

