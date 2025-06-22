#include "constant.h"

std::string constant::folder_name = ".";
std::string file_name_results;
int constant::nbPasswordFound = 0;
//std::vector<QString> constant::passwordFound;
//std::map<QString,QString> constant::finalResults;
std::string constant::username = u8"";
std::unordered_map<std::string, std::unordered_map<std::string, std::string>> constant::softwares_path = {
    {"Dpapi",
        {
            {"local", u8"{root}Users/{user}/AppData/"},
            {"remote", u8"{root}Users/{user}/DPAPI"},
        },
    },
    {"Wifi",
        {
            {"local",  "{root}ProgramData/Microsoft/Wlansvc/Profiles/Interfaces"},
            {"remote", "{root}System/Wifi/Interfaces"}
        }
    },
    {"Chrome",
        {
            {"local",  "{root}Users/{user}/AppData/Local/Google/Chrome/User Data"},
            {"remote", "{root}Users/{user}/Chrome"}
        }
    },
    {"Hives",
        {
            {"local","{root}Windows/System32/config"},
            {"remote","{root}System/Hives"}
        }
    },
    {"Dpapi_system",
        {
            {"local","{root}Windows/System32/Microsoft"},
            {"remote","{root}System/DPAPI/",}
        },
    },
    
};
//std::vector<QString> constant::hives;
bool constant::quiet_mode = false;
std::string constant::drive = u8"C";
std::string constant::dump = "local";
std::string constant::root_dump = "";
Decrypt_DPAPI* constant::user_dpapi = nullptr;
unsigned char* constant::user_password = nullptr;
unsigned char* constant::user_pwdhash = nullptr;
