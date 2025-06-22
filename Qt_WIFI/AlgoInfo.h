#pragma once
#include<map>
#include<string>

struct Algoinfo
{
    std::string name;
    int keyLength;
    int blockLength;
    int IVLength;
    int module;
    int digestLength;
    void(*keyFixup)(uint8_t*, size_t);
    //mbedtls_algoid algoid;
};

class Algo
{
public:
    Algo(std::map<int, Algoinfo>* algoMap);
    static const uint8_t odd_parity_lut[256];
    static void des_set_odd_parity(uint8_t* key, size_t length);
    void add_algo(std::map<int, Algoinfo>* Algo);
};

