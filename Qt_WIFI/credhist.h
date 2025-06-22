#pragma once
#include<map>
#include<string>
#include<windows.h>
#include"config/DPAPI/structures.h"
#include"config/DPAPI/crypto.h"
class CredhistEntry
{
public:
	CredhistEntry(CRED_HIST* credhist) :credhist(credhist) {};
	void decrypt_with_key(const std::vector<unsigned char>& enckey);
	void decrypt_with_hash(const std::vector<unsigned char>& pwdhash);
	BYTE* ntlm = nullptr;
	std::vector<unsigned char> pwdhash;
	CRED_HIST* credhist;
};
class CredHistFile
{
public:
	CredHistFile() = default;
	CredHistFile(const std::string& credhist);
	CRED_HIST_FILE credhistfile;
	std::string credhist;
	std::vector<CredhistEntry> entries_list;
	bool valid = false;
};

