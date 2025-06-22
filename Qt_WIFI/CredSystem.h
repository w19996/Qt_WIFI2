#pragma once
#include <vector>
#include <string>
#include "config/DPAPI/structures.h"
class CredSystem
{
public:
	void CreatCredSystem(const std::vector<unsigned char> dpapi_system);
	const CRED_SYSTEM* cred_system;
	int revision;
	std::vector<unsigned char> machine;
	std::vector<unsigned char> user;
};

