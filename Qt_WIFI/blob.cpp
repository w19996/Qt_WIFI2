#include "blob.h"

const mbedtls_cipher_info_t* info_from_cipherAlgo2(std::string hname, std::string moudle)
{
    if (moudle == "CBC")
    {
        if (hname == "AES") return mbedtls_cipher_info_from_string("AES-128-CBC");
        if (hname == "AES-128") return mbedtls_cipher_info_from_string("AES-128-CBC");
        if (hname == "AES-192") return mbedtls_cipher_info_from_string("AES-192-CBC");
        if (hname == "AES-256") return mbedtls_cipher_info_from_string("AES-256-CBC");
        if (hname == "DES") return mbedtls_cipher_info_from_string("DES-CBC");
        if (hname == "DES3") return mbedtls_cipher_info_from_string("DES-EDE3-CBC");
    }
    return nullptr;
}
bool DPAPIBlob::decrypt(const std::vector<uint8_t>& masterkey, std::vector<uint8_t>* entropy, std::vector<uint8_t>* strongPassword)
{
    using CryptoFunc = std::function<std::vector<uint8_t>(
        const std::vector<uint8_t>&,
        const std::vector<uint8_t>&,
        ALG_ID,
        const std::vector<uint8_t>*,
        const std::vector<uint8_t>*,
        const std::vector<uint8_t>*)>;

    std::vector<CryptoFunc> algos = {CryptSessionKeyXP, CryptSessionKeyWin7};
    std::vector<uint8_t> nonce(this->dpapiblob._keyMaterial->pbSalt, this->dpapiblob._keyMaterial->pbSalt + this->dpapiblob._keyMaterial->dwSaltLen);
    for (const auto& algo : algos)
    {
        auto sessionkey = algo(masterkey, nonce, this->dpapiblob._keyMaterial->algHash, entropy, strongPassword, nullptr);
        auto key = CryptDeriveKey(sessionkey, this->dpapiblob._keyMaterial->algCrypt, this->dpapiblob._keyMaterial->algHash);
        std::vector<uint8_t> iv((*AlgorithmInfo).find(this->dpapiblob._keyMaterial->algCrypt)->second.blockLength, 0);

        mbedtls_cipher_context_t ctx;
        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info_from_cipherAlgo2((*AlgorithmInfo).find(this->dpapiblob._keyMaterial->algCrypt)->second.name, "CBC"));
        mbedtls_cipher_setkey(&ctx, key.data(), ((*AlgorithmInfo).find(this->dpapiblob._keyMaterial->algCrypt)->second.keyLength)*8, MBEDTLS_DECRYPT);
        mbedtls_cipher_set_iv(&ctx, iv.data(), iv.size());
        mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
        mbedtls_cipher_reset(&ctx);
        std::vector<uint8_t> cleartext(this->dpapiblob._keyMaterial->dwDataLen + (*AlgorithmInfo).find(this->dpapiblob._keyMaterial->algCrypt)->second.blockLength);
        size_t olen = 0, finish_olen = 0;
        mbedtls_cipher_update(&ctx, this->dpapiblob._keyMaterial->pbData, this->dpapiblob._keyMaterial->dwDataLen, cleartext.data(), &olen);
        mbedtls_cipher_finish(&ctx, cleartext.data() + olen, &finish_olen);
        cleartext.resize(olen + finish_olen);
        mbedtls_cipher_free(&ctx);

        uint8_t padding = cleartext.back();
        if (padding > 0 && padding <= (*AlgorithmInfo).find(this->dpapiblob._keyMaterial->algCrypt)->second.blockLength)
            cleartext.resize(cleartext.size() - padding);
        this->cleartext.assign(cleartext.begin(), cleartext.begin() + std::strlen((const char*)cleartext.data()));
        std::vector<uint8_t> hmac_data(this->dpapiblob._keyMaterial->pbHmack2Key, this->dpapiblob._keyMaterial->pbHmack2Key + this->dpapiblob._keyMaterial->dwHmac2KeyLen);
        std::vector<uint8_t> verifBlob;

        auto signComputed = algo(masterkey, hmac_data, this->dpapiblob._keyMaterial->algHash, entropy,nullptr, &(this->dpapiblob.verifBlob));
        this->decrypted =( signComputed.size() == this->dpapiblob._keyMaterial->dwSignLen && std::equal(signComputed.begin(), signComputed.end(), this->dpapiblob._keyMaterial->pbSign));
        if (this->decrypted)
            return true;

    }
    this->decrypted = false;
    return this->decrypted;
}
std::tuple<bool, std::optional<QString>> DPAPIBlob::decrypt_encrypted_blob(MasterKeyPool* mkp, std::string entropy_hex)
{
    QUuid uuid(this->dpapiblob._keyMaterial->guidMasterKey);
    qDebug() << uuid;
    qDebug() << uuid.toString(QUuid::WithoutBraces).toStdString();
    auto mks = mkp->get_master_keys(uuid.toString(QUuid::WithoutBraces).toStdString());
    qDebug() << mks.has_value();

    if (!mks.has_value())
        return { false,std::nullopt };
    QByteArray entropy;

    qDebug() << entropy_hex;
    if (!entropy_hex.empty())
    {
        entropy = QByteArray::fromHex(QByteArray::fromStdString(entropy_hex));
        qDebug() << entropy.toHex();
    }
    for (auto& mk : *mks)
    {
        qDebug() << mk->decrypted;
        if (mk->decrypted)
        {
            qDebug() << mk->decrypted;
            std::vector<uint8_t> vec(entropy.begin(), entropy.end());
            this->decrypt(mk->get_key(), &vec);
            if (this->decrypted)
                qDebug() << mk->decrypted;
                return { true,this->cleartext };
        }
    }
    return { false,std::nullopt };
}