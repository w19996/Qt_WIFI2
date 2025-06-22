#include "credhist.h"
#include <sddl.h>  // 包含 SID 字符串转换函数


void CredhistEntry::decrypt_with_hash(const std::vector<unsigned char>& pwdhash)
{
	
	LPWSTR sidStr = nullptr;
	ConvertSidToStringSidW(this->credhist->SID, &sidStr);//二进制转字符串
	
	QString qs = QString::fromWCharArray(sidStr);
	std::string utf8 = qs.toUtf8().constData();  // std::string utf8

	this->decrypt_with_key(derivePwdHash(pwdhash, utf8));
	LocalFree(sidStr);
}
void CredhistEntry::decrypt_with_key(const std::vector<unsigned char>& enckey)
{
	
}

CredHistFile::CredHistFile(const std::string &credhist) :credhist(credhist)
{
	this->credhistfile.CREAT_CRED_HIST_FILE(this->credhist);
	if (this->credhistfile.cred_hist_file->cred_hist)//一般不会执行
	{
		CredhistEntry c(this->credhistfile.cred_hist_file->cred_hist);
		this->entries_list.push_back(c);
	}
}
