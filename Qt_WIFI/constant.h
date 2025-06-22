#pragma once

#include<string>
#include<vector>
#include<map>
#include<unordered_map>
#include<config/dpapi.h>
class Decrypt_DPAPI;

class constant
{
public:
    static std::string folder_name;
    static std::string file_name_results;
    static int nbPasswordFound;
    static std::vector<std::string> passwordFound;
    static std::map<std::string, std::string> finalResults;
    static std::string username;
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> softwares_path;
    static std::vector<std::string> hives;
    static bool quiet_mode;
    static std::string drive;
    static std::string dump;
    static std::string root_dump;
    static Decrypt_DPAPI* user_dpapi;
    static unsigned char* user_password;
    static unsigned char* user_pwdhash;
};


