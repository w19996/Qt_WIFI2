#pragma once

#include <string>
#include <regex>
#include "constant.h"
std::string build_path(std::string software_name);
std::string format_path(const std::string& template_path, const std::string& unreplace, const std::string& replace);

