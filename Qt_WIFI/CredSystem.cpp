#include "CredSystem.h"
void CredSystem::CreatCredSystem(const std::vector<unsigned char> dpapi_system)
{
	this->cred_system = reinterpret_cast<const CRED_SYSTEM*>(dpapi_system.data());
	this->revision = this->cred_system->revision;
	this->machine.assign(std::begin(this->cred_system->machine),std::end(this->cred_system->machine));
	this->user.assign(std::begin(this->cred_system->user), std::end(this->cred_system->user));
}