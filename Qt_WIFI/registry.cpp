#include "registry.h"



//BOOL Privilege::SetPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege)  // to enable or disable privilege
//{
//    //HANDLE hToken;
//    TOKEN_PRIVILEGES tp;
//    LUID luid;
//    TOKEN_PRIVILEGES tpPrevious;
//    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
//    BOOL bSuccess = FALSE;
//
//    if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid)) return FALSE;
//
//    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &_hProcessToken))
//        return FALSE;
//
//    //
//    // first pass.  get current privilege setting
//    //
//    tp.PrivilegeCount = 1;
//    tp.Privileges[0].Luid = luid;
//    tp.Privileges[0].Attributes = 0;
//
//    AdjustTokenPrivileges(_hProcessToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
//
//    if (GetLastError() == ERROR_SUCCESS) {
//        //
//        // second pass.  set privilege based on previous setting
//        //
//        tpPrevious.PrivilegeCount = 1;
//        tpPrevious.Privileges[0].Luid = luid;
//
//        if (bEnablePrivilege)
//            tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
//        else
//            tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
//
//        AdjustTokenPrivileges(_hProcessToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
//
//        if (GetLastError() == ERROR_SUCCESS)
//            bSuccess = TRUE;
//        else
//            qDebug() << Logger::winError(GetLastError());
//        CloseHandle(_hProcessToken);
//    }
//    else {
//        DWORD dwErrorCode = GetLastError();
//        qDebug() << Logger::winError(GetLastError());
//        CloseHandle(_hProcessToken);
//        SetLastError(dwErrorCode);
//    }
//
//    return bSuccess;
//}
//void Privilege::LoadRegPrivilege(BOOL tag)
//{
//    //OpenProcess(MAXIMUM_ALLOWED, FALSE, _dwProcessId);
//
//    if (!SetPrivilege(SE_BACKUP_NAME, tag) || !SetPrivilege(SE_RESTORE_NAME, tag))
//    {
//        _tprintf(TEXT("SetPrivilege failed.\n"));
//        CloseHandle(_hProcessToken);
//        return;
//    }
//
//    //ImpersonateLoggedOnUser(_hToken);
//}
//
////void Privilege::FullRegPrivilege(BOOL tag)
////{
////    //HANDLE hProcess = NULL, hProcessToken = NULL;
////    DWORD dwProcessId = GetProcessIdByName(TEXT("winlogon.exe"));
////    qDebug() << "dwProcessId：" << dwProcessId;
////    if (!SetPrivilege(SE_DEBUG_NAME, tag))
////    {
////        qDebug() << Logger::winError(GetLastError());
////        return;
////    }
////    if (!SetPrivilege(SE_BACKUP_NAME, tag))
////    {
////        qDebug() << Logger::winError(GetLastError());
////        return;
////    }
////    if (!SetPrivilege(SE_RESTORE_NAME, tag))
////    {
////        qDebug() << Logger::winError(GetLastError());
////        return;
////    }
////    _hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
////    if (!_hProcess)
////    {
////        CloseHandle(_hProcess);
////        qDebug() << Logger::winError(GetLastError());
////    }
////
////    if (!OpenProcessToken(_hProcess, MAXIMUM_ALLOWED, &_hProcessToken))
////    {
////        CloseHandle(_hProcessToken);
////        qDebug() << Logger::winError(GetLastError());
////    }
////    if (!ImpersonateLoggedOnUser(_hProcessToken))
////    {
////        CloseHandle(_hProcessToken);
////        qDebug() << Logger::winError(GetLastError());
////    }
////    if (_hProcess)
////        CloseHandle(_hProcess);
////    if (_hProcessToken)
////        CloseHandle(_hProcessToken);
////}
//
//void Privilege::FullRegPrivilege(BOOL enable)
//{
//    DWORD dwProcessId = GetProcessIdByName(TEXT("winlogon.exe"));
//    qDebug() << "dwProcessId：" << dwProcessId;
//    if (dwProcessId == 0) {
//        qWarning() << "无法找到 winlogon.exe";
//        return;
//    }
//
//    // 提升当前进程权限（自身进程）
//    if (!SetPrivilege(SE_DEBUG_NAME, enable) ||
//        !SetPrivilege(SE_BACKUP_NAME, enable) ||
//        !SetPrivilege(SE_RESTORE_NAME, enable))
//    {
//        qWarning() << "提权失败：" << Logger::winError(GetLastError());
//        return;
//    }
//
//    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
//    if (!hProcess) {
//        qWarning() << "OpenProcess 失败：" << Logger::winError(GetLastError());
//        return;
//    }
//
//    HANDLE hToken = nullptr;
//    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
//        qWarning() << "OpenProcessToken 失败：" << Logger::winError(GetLastError());
//        CloseHandle(hProcess);
//        return;
//    }
//
//    HANDLE hDupToken = nullptr;
//    if (!DuplicateToken(hToken, SecurityImpersonation, &hDupToken)) {
//        qWarning() << "DuplicateToken 失败：" << Logger::winError(GetLastError());
//        CloseHandle(hToken);
//        CloseHandle(hProcess);
//        return;
//    }
//
//    if (!ImpersonateLoggedOnUser(hDupToken)) {
//        qWarning() << "ImpersonateLoggedOnUser 失败：" << Logger::winError(GetLastError());
//        CloseHandle(hDupToken);
//        CloseHandle(hToken);
//        CloseHandle(hProcess);
//        return;
//    }
//
//    // impersonation 成功后，只保存 token，不关闭
//    _hProcessToken = hDupToken;
//
//    CloseHandle(hToken);   // hToken 是原始 token，不再需要
//    CloseHandle(hProcess); // hProcess 也不再需要
//}
//
//
//DWORD Privilege::GetProcessIdByName(LPCTSTR processName)
//{
//    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    if (hSnapshot == INVALID_HANDLE_VALUE)
//    {
//        _tprintf(TEXT("CreateToolhelp32Snapshot failed: %u\n"), GetLastError());
//        return 0;
//    }
//
//    PROCESSENTRY32 pe;
//    pe.dwSize = sizeof(PROCESSENTRY32);
//
//    if (Process32First(hSnapshot, &pe))
//    {
//        do
//        {
//            if (_tcsicmp(pe.szExeFile, processName) == 0)
//            {
//                CloseHandle(hSnapshot);
//                return pe.th32ProcessID;
//            }
//        } while (Process32Next(hSnapshot, &pe));
//    }
//
//    _tprintf(TEXT("Process not found.\n"));
//    CloseHandle(hSnapshot);
//    return 0;
//}
//
//
//Hive::Hive(const QString& header)
//{
//    QString uuid = QUuid::createUuid().toString();
//    uuid = uuid.mid(1, uuid.length() - 2).replace("-", "");
//    this->subKey = header + uuid;
//}
//
//
//void Hive::LoadReg(const QString& path)
//{
//    LSTATUS result;
//
//    Privilege* p = new Privilege;
//    p->LoadRegPrivilege(TRUE);
//    qDebug() << this->subKey;
//    result = RegLoadKey(HKEY_LOCAL_MACHINE, this->subKey.toStdWString().c_str(), path.toStdWString().c_str());
//    qDebug() << "LoadReg：" << Logger::winError(result);
//    p->LoadRegPrivilege(FALSE);
//    delete p;
//
//}

//void unLoadRegThread::run()
//{
//    LSTATUS result;
//    Privilege* p = new Privilege;
//    p->LoadRegPrivilege(TRUE);
//    result = RegUnLoadKey(HKEY_LOCAL_MACHINE, this->subKey.toStdWString().c_str());
//    qDebug() << "unLoadReg：" << Logger::winError(result);
//    p->LoadRegPrivilege(FALSE);
//    delete p;
//}
//
//void Hive::unLoadReg()
//{
//    LSTATUS result;
//    Privilege* p = new Privilege;
//    p->LoadRegPrivilege(TRUE);
//    result = RegUnLoadKey(HKEY_LOCAL_MACHINE, this->subKey.toStdWString().c_str());
//    qDebug() << "unLoadReg：" << Logger::winError(result);
//    p->LoadRegPrivilege(FALSE);
//    delete p;
//    //unLoadRegThread unLoadreg(this->subKey);
//
//}



PrivilegeManager::PrivilegeManager()
    : _hProcess(nullptr), _hProcessToken(nullptr) {}

PrivilegeManager::~PrivilegeManager() {
    if (_hProcessToken) CloseHandle(_hProcessToken);
    if (_hProcess) CloseHandle(_hProcess);
}

bool PrivilegeManager::SetPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp = {};
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
    BOOL bSuccess = FALSE;

    if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid)) return FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &_hProcessToken))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(_hProcessToken, FALSE, &tp, sizeof(tp), &tpPrevious, &cbPrevious);

    if (GetLastError() == ERROR_SUCCESS) {
        tpPrevious.PrivilegeCount = 1;
        tpPrevious.Privileges[0].Luid = luid;

        if (bEnablePrivilege)
            tpPrevious.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
        else
            tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

        AdjustTokenPrivileges(_hProcessToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);

        if (GetLastError() == ERROR_SUCCESS)
            bSuccess = TRUE;
        else
            qDebug() << Logger::winError(GetLastError());
    }
    else {
        DWORD err = GetLastError();
        SetLastError(err);
    }
    return bSuccess;
}

bool PrivilegeManager::LoadRegPrivilege(BOOL tag) {
    return SetPrivilege(SE_BACKUP_NAME, tag) && SetPrivilege(SE_RESTORE_NAME, tag);
}

bool PrivilegeManager::FullRegPrivilege(BOOL tag) {
    DWORD dwProcessId = GetProcessIdByName(TEXT("winlogon.exe"));
    if (!SetPrivilege(SE_DEBUG_NAME, tag) ||
        !SetPrivilege(SE_BACKUP_NAME, tag) ||
        !SetPrivilege(SE_RESTORE_NAME, tag)) {
        return false;
    }

    _hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
    if (!_hProcess) {
        return false;
    }

    if (!OpenProcessToken(_hProcess, MAXIMUM_ALLOWED, &_hProcessToken)) {
        return false;
    }

    if (!ImpersonateLoggedOnUser(_hProcessToken)) {
        return false;
    }

    return true;
}

DWORD PrivilegeManager::GetProcessIdByName(LPCTSTR processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcsicmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

bool PrivilegeManager::openRegistryKey(const QString& subkey, REGSAM samDesired, HKEY* phKey, HKEY hkey)
{
    this->FullRegPrivilege(TRUE);
    LONG res = RegOpenKeyExW(hkey, subkey.toStdWString().c_str(), 0, samDesired, phKey);
    qDebug() << "openRegistryKey" << Logger::winError(res);
    this->FullRegPrivilege(FALSE);
    RevertToSelf();
    return res == ERROR_SUCCESS;
}

bool PrivilegeManager::loadHive(const QString& subKey, const QString& hiveFile)
{

    this->LoadRegPrivilege(TRUE);

    LONG res = RegLoadKeyW(HKEY_LOCAL_MACHINE,
        subKey.toStdWString().c_str(),
        hiveFile.toStdWString().c_str());
    this->LoadRegPrivilege(FALSE);
    RevertToSelf();
    qDebug() << Logger::winError(res);
    return res == ERROR_SUCCESS;
}

bool PrivilegeManager::unloadHive(const QString& subKey)
{
    this->LoadRegPrivilege(TRUE);

    LONG res = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, subKey.toStdWString().c_str());
    qDebug() << Logger::winError(res);
    this->LoadRegPrivilege(FALSE);
    RevertToSelf();
    return res == ERROR_SUCCESS;
}



QByteArray Regedit::get_syskey(const std::string& system)
{
    QString uuid = QUuid::createUuid().toString();
    uuid = uuid.mid(1, uuid.length() - 2).replace("-", "");
    QString subKey = "Hive_sys_" + uuid;
    QString wsystem = QString::fromStdString(system);

	HKEY hKey = nullptr;
	DWORD current = 0;
	DWORD dataSize = sizeof(DWORD);
	DWORD dataType = 0;
    
    PrivilegeManager sys;
    sys.loadHive(subKey, wsystem);
    
	QString system_select = subKey + "\\Select";

    LSTATUS ret;

    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, system_select.toStdWString().c_str(), 0, KEY_READ, &hKey);

    qDebug() << subKey << "RegOpenKeyExW：" << Logger::winError(ret);

	ret = RegQueryValueEx(hKey, L"Current", nullptr, &dataType, reinterpret_cast<LPBYTE>(&current), &dataSize);
    qDebug() << subKey << "RegQueryValueExW：" << Logger::winError(ret);
	ret = RegCloseKey(hKey);
    qDebug() << subKey << "RegCloseKey：" << Logger::winError(ret);

    

	QString Lsa_path = QString(subKey + "\\ControlSet%1\\Control\\Lsa").arg(current, 3, 10, QChar('0'));
	QStringList subkeys = { "JD", "Skew1", "GBG", "Data" };
	QByteArray syskey;

	for (const QString& sub : subkeys)
	{
		QString fullPath = Lsa_path + "\\" + sub;

		HKEY hsubKey = nullptr;

        ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reinterpret_cast<const wchar_t*>(fullPath.utf16()), 0, KEY_READ, &hsubKey);

        qDebug() << fullPath << "RegOpenKeyExW：" << Logger::winError(ret);

		wchar_t className[256] = { 0 };
		DWORD classSize = sizeof(className) / sizeof(wchar_t);
        ret = RegQueryInfoKey(hsubKey, className, &classSize, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        qDebug() << fullPath << "RegQueryInfoKeyW：" << Logger::winError(ret);

        ret = RegCloseKey(hsubKey);
        qDebug() << fullPath << "RegCloseKey：" << Logger::winError(ret);

		QString classStr = QString::fromWCharArray(className, classSize);
		QByteArray part = QByteArray::fromHex(classStr.toLatin1());
		syskey.append(part);
	}
	int transforms[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
	QByteArray skey;
    
	for (const auto& tmp : transforms)
	{
		skey.append(syskey[tmp]);
	}

    sys.unloadHive(subKey);
    

    qDebug() << skey.toHex();
	return skey;
}

std::vector<uint8_t> Regedit::get_lsa_key(const std::string& security)
{
    LSTATUS ret;
    std::vector<BYTE> lsakey;
	if (!this->syskey.empty())
	{
        QString wsecurity = QString::fromStdString(security);

        QString uuid = QUuid::createUuid().toString();
        uuid = uuid.mid(1, uuid.length() - 2).replace("-", "");
        QString subKey = "Hive_sec_" + uuid;

        BYTE buffer[4] = {};
        DWORD dataSize = sizeof(buffer);
        DWORD dataType = 0;

        PrivilegeManager sec;
        sec.loadHive(subKey, wsecurity);
        QString PolRevision = subKey + "\\Policy\\PolRevision";        
        qDebug() << subKey;

        HKEY hKey = nullptr;
        sec.openRegistryKey(PolRevision, KEY_READ, &hKey);
        
        ret = RegQueryValueExW(hKey, L"", nullptr, &dataType, buffer, &dataSize);
        qDebug() << "get_lsa_key_RegQueryValueExW" << Logger::winError(ret);
        ret = RegCloseKey(hKey);
        qDebug() << "get_lsa_key_RegCloseKey" << Logger::winError(ret);

        POL_REVISION pol = {};
        std::memcpy(&(pol.minor), buffer, 2);
        std::memcpy(&(pol.major), buffer + 2, 2);
        this->policy = QString("%1.%2").arg(pol.major).arg(pol.minor, 2, 10, QChar('0')).toDouble();
        qDebug() << this->policy;
        if (this->policy > 1.09)
        {
            HKEY hKey = nullptr;
            
            DWORD dataSize = 0;
            DWORD dataType = 0;

            QString PolEKList = subKey + "\\Policy\\PolEKList";
            sec.openRegistryKey(PolEKList, KEY_READ, &hKey);
            //ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PolEKList.toStdWString().c_str(), 0, KEY_READ, &hKey);
            //qDebug() << "get_lsa_key_RegOpenKeyExW" << Logger::winError(ret);
            ret = RegQueryValueExW(hKey, L"", nullptr, nullptr, nullptr, &dataSize);
            qDebug() << "get_lsa_key_RegQueryValueExW" << Logger::winError(ret);
            lsakey.resize(dataSize);
            ret = RegQueryValueExW(hKey, L"", nullptr, &dataType, lsakey.data(), &dataSize);
            qDebug() << "get_lsa_key_RegQueryValueExW" << Logger::winError(ret);
            ret = RegCloseKey(hKey);
            qDebug() << "get_lsa_key_RegCloseKey" << Logger::winError(ret);
        }
        else
        {
            HKEY hKey = nullptr;
            
            DWORD dataSize = 0;
            DWORD dataType = 0;

            QString PolEKList = subKey + "\\Policy\\PolSecretEncryptionKey";
            ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PolEKList.toStdWString().c_str(), 0, KEY_READ, &hKey);
            qDebug() << "get_lsa_key_RegOpenKeyExW" << Logger::winError(ret);
            ret = RegQueryValueExW(hKey, L"", nullptr, nullptr, nullptr, &dataSize);
            qDebug() << "get_lsa_key_RegQueryValueExW" << Logger::winError(ret);
            lsakey.resize(dataSize);
            ret = RegQueryValueExW(hKey, L"", nullptr, &dataType, lsakey.data(), &dataSize);
            qDebug() << "get_lsa_key_RegQueryValueExW" << Logger::winError(ret);
            ret = RegCloseKey(hKey);
            qDebug() << "get_lsa_key_RegCloseKey" << Logger::winError(ret);
        }
        sec.unloadHive(subKey);
	}
    

    std::vector<uint8_t> rv;
    
    qDebug() << lsakey;
    if (this->policy > 1.09)
    {
        qDebug() << this->policy;
        std::pair<std::string, std::map<std::string, key_type>> tmp = decrypt_lsa_key_nt6(lsakey, this->syskey);
        qDebug() << tmp.first;
        for (const auto& [key, val] : tmp.second)
        {
            qDebug() << key << "：" << val.key << "：" << val.type;
        }
        
        std::string currentKey = tmp.first;
        this->lsakeys = tmp.second;
        rv = this->lsakeys[currentKey].key;
    }
    else
    {

    }
    return rv;
}

std::map<QString, std::map<QString, std::vector<uint8_t>>> Regedit::get_lsa_secrets(std::string security, std::string system)
{
    LSTATUS re;
    qDebug() << "get_lsa_secrets";
    std::map<QString, std::map<QString, std::vector<uint8_t>>> lsa_secrets;
    QByteArray ret = this->get_syskey(system);
    qDebug() << "get_lsa_secrets";
    this->syskey.assign(ret.begin(), ret.end());
    qDebug() << ret.toHex();

    std::vector<uint8_t> currentKey(this->get_lsa_key(security));
    //this->get_lsa_key(security);
    qDebug() << "get_lsa_secrets";

    QString wsystem = QString::fromStdString(security);

    QString uuid = QUuid::createUuid().toString();
    uuid = uuid.mid(1, uuid.length() - 2).replace("-", "");
    QString subKey = "Hive_sec_" + uuid;

    PrivilegeManager sec;

    
    sec.loadHive(subKey, wsystem);

    QString Secrets = subKey + "\\Policy\\Secrets";

    
    HKEY hKey = nullptr;

    sec.openRegistryKey(Secrets, KEY_READ, &hKey);

    //if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Secrets.toStdWString().c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    //    return {};

    DWORD index = 0;
    wchar_t sub_key_name[256];
    DWORD sub_key_name_size = 256;

    while ((re = RegEnumKeyExW(hKey, index++, sub_key_name, &sub_key_name_size, nullptr, nullptr, nullptr, nullptr)) == ERROR_SUCCESS)
    {
        qDebug() <<"index："<< index << Logger::winError(re);
        QString key_name(sub_key_name);
        qDebug() << key_name;
        lsa_secrets[key_name] = {};

        HKEY hSubKey = nullptr;
        if (sec.openRegistryKey(key_name, KEY_READ, &hSubKey, hKey));//RegOpenKeyExW(hKey, key_name.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
        {
            DWORD sub_index = 0;
            wchar_t val_key[256];
            DWORD val_key_len = 256;

            while ((re = RegEnumKeyExW(hSubKey, sub_index++, val_key, &val_key_len, nullptr, nullptr, nullptr, nullptr)) == ERROR_SUCCESS)
            {
                qDebug() <<"sub_index："<< sub_index << Logger::winError(re);
                HKEY hValSubKey = nullptr;
                QString Qval_key(val_key);
                qDebug() << Qval_key;
                if (sec.openRegistryKey(Qval_key, KEY_READ, &hValSubKey, hSubKey))//RegOpenKeyExW(hSubKey, val_key, 0, KEY_READ, &hValSubKey) == ERROR_SUCCESS)
                {
                    DWORD val_type = 0;
                    DWORD val_size = 0;
                    if ((re = RegQueryValueExW(hValSubKey, L"", nullptr, &val_type, nullptr, &val_size)) == ERROR_SUCCESS && val_size > 0)
                    {
                        qDebug() << Logger::winError(re);
                        std::vector<uint8_t> value_data(val_size);
                        if ((re = RegQueryValueExW(hValSubKey, L"", nullptr, nullptr, value_data.data(), &val_size)) == ERROR_SUCCESS)
                        {
                            qDebug() << Logger::winError(re);
                            lsa_secrets[key_name][Qval_key] = std::move(value_data);
                            qDebug() << lsa_secrets[key_name][Qval_key];
                        }
                    }
                    re = RegCloseKey(hValSubKey);
                    qDebug() << Logger::winError(re);
                }
                val_key_len = 256;
            }
            re = RegCloseKey(hSubKey);
            qDebug() << Logger::winError(re);
        }
        sub_key_name_size = 256;
    }
    re = RegCloseKey(hKey);
    sec.unloadHive(subKey);
    qDebug() << Logger::winError(re);


    for (auto& [k, v] : lsa_secrets)
    {
        for (const auto& s : { QString(L"CurrVal"), QString(L"OldVal") })
        {
            if (!v[s].empty())
            {
                if (this->policy > 1.09)
                {
                    lsa_secrets[k][s] = decrypt_lsa_secret(v[s], this->lsakeys);  // 你应实现                                   
                    qDebug() << k << "：" << s << "：" << lsa_secrets[k][s];
                }
                else
                {
                    //lsa_secrets[k][s] = SystemFunction005(std::vector<uint8_t>(v[s].begin() + 0x0c, v[s].end()), currentKey);
                }
            }
        }

        for (const auto& s : { QString(L"CupdTime"), QString(L"OupdTime") })
        {
            if (!v[s].empty())
            {
                //SYSTEMTIME st = parse_system_time(v[s]);  // 自定义解析 FILETIME 的函数
                // 转换为字符串或 std::chrono::system_clock::time_point 自行处理
            }
        }
    }


    return lsa_secrets;
}
Regedit::~Regedit()
{

}