#include "utils.h"
#include<QDebug>
std::string capitalize(const std::string& str) {
    if (str.empty()) return str;
    std::string result = str;
    result[0] = static_cast<char>(toupper(result[0]));
    for (size_t i = 1; i < result.size(); ++i) {
        result[i] = static_cast<char>(tolower(result[i]));
    }
    return result;
}


/*
std::string format_path(const std::string& path_template, const std::string& root, const std::string& user) {
    std::string path = path_template;
    size_t pos;
    while ((pos = path.find("{root}")) != std::string::npos) {
        path.replace(pos, 6, root);
    }
    while ((pos = path.find("{user}")) != std::string::npos) {
        path.replace(pos, 6, user);
    }
    return path;
}
*/

std::string format_path(const std::string& template_path, const std::string& unreplace, const std::string& replace)
{
    std::string result = template_path;
    // 使用正则替换 {root}
    result = std::regex_replace(result, std::regex(unreplace), replace);
    //qDebug()<<result;
    // 使用正则替换 {user}
    //result = std::regex_replace(result, std::regex(unreplace2), replace2);
    return result;
}
std::string build_path(std::string software_name)
{
    // 首字母大写
    std::string capitalized_name = capitalize(software_name);
    //qDebug()<<capitalized_name;
    // 获取模板并格式化
    std::string path_template = constant::softwares_path[capitalized_name][constant::dump];
    //qDebug()<<path_template;
    std::string path = format_path(path_template, "\\{root\\}", constant::root_dump);
    path = format_path(path, "\\{user\\}", constant::username);
    //qDebug()<<path;
    return path;
}
