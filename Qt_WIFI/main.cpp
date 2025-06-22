#include"widget.h"
#include"wifi.h"
#include<QApplication>
#include<log/logger.h>
#include<QString>

#include"config/DPAPI/crypto.h"

#include<QDebug>

#pragma comment(lib, "bcrypt.lib")

std::map<int, Algoinfo>* AlgorithmInfo = new std::map<int, Algoinfo>;
int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    QApplication a(argc, argv);

    Logger::initialize(FALSE);
    //Logger::setMinimumLevel(QtInfoMsg); // 忽略 debug 输出，最低记录 Info
    Widget w;
    w.show();
    

    //wifi ab;

    //ab.run("wifi");
    return a.exec();
}

//
//extern "C" {
//#include "mbedtls/md.h"
//#include "mbedtls/pkcs5.h"
//}
//
//#include <cstring>
//#include <iostream>
//
//#pragma comment(lib, "bcrypt.lib")
//
//int main() {
//    const char* password = "password123";
//    const unsigned char salt[] = "saltvalue";
//    const int iterations = 10000;
//    const size_t key_len = 32;
//
//    unsigned char key[32] = { 0 };
//
//    mbedtls_md_context_t ctx;
//    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
//
//    mbedtls_md_init(&ctx);
//    mbedtls_md_setup(&ctx, info, 1);
//
//    mbedtls_pkcs5_pbkdf2_hmac(&ctx,
//        (const unsigned char*)password, strlen(password),
//        salt, sizeof(salt),
//        iterations,
//        key_len, key);
//
//    mbedtls_md_free(&ctx);
//
//    std::cout << "Derived Key: ";
//    for (size_t i = 0; i < key_len; ++i)
//        printf("%02x", key[i]);
//    std::cout << std::endl;
//
//    return 0;
//}
