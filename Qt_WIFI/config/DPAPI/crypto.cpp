#include "crypto.h"

QUuid uuidFromLittleEndian(const QByteArray& data)
{
    Q_ASSERT(data.size() == 16); // 必须正好 16 字节

    const uchar* raw = reinterpret_cast<const uchar*>(data.constData());

    quint32 data1 = (raw[3] << 24) | (raw[2] << 16) | (raw[1] << 8) | raw[0];      // <L
    quint16 data2 = (raw[5] << 8) | raw[4];                                        // <H
    quint16 data3 = (raw[7] << 8) | raw[6];                                        // <H

    return QUuid(data1, data2, data3,
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}
QByteArray pbkdf2( const QByteArray& password, const QByteArray& salt, int iterations, int keyLen,std::string hname)
{
    QByteArray result;
    int block_index = 1;

    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string(hname.c_str());
    size_t hash_len = mbedtls_md_get_size(md_info);
    std::vector<unsigned char> derived(hash_len);
    std::vector<unsigned char> actual(hash_len);

    while (result.size() < keyLen) {
        // Step 1: U = salt + block_index
        QByteArray U = salt;
        U.append((block_index >> 24) & 0xFF);
        U.append((block_index >> 16) & 0xFF);
        U.append((block_index >> 8) & 0xFF);
        U.append((block_index) & 0xFF);
        block_index++;

        // U_1 = HMAC(password, U)
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md_info, 1);
        mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const unsigned char*>(password.constData()), password.size());
        mbedtls_md_hmac_update(&ctx, reinterpret_cast<const unsigned char*>(U.constData()), U.size());
        mbedtls_md_hmac_finish(&ctx, derived.data());
        mbedtls_md_free(&ctx);

        // Iteratively XOR
        for (int r = 1; r < iterations; ++r) {
            mbedtls_md_context_t ctx2;
            mbedtls_md_init(&ctx2);
            mbedtls_md_setup(&ctx2, md_info, 1);
            mbedtls_md_hmac_starts(&ctx2, reinterpret_cast<const unsigned char*>(password.constData()), password.size());
            mbedtls_md_hmac_update(&ctx2, derived.data(), hash_len);
            mbedtls_md_hmac_finish(&ctx2, actual.data());
            mbedtls_md_free(&ctx2);

            for (size_t j = 0; j < hash_len; ++j) {
                derived[j] ^= actual[j];
            }
        }

        // Append result
        result.append(reinterpret_cast<const char*>(derived.data()), std::min<int>(keyLen - result.size(), hash_len));
    }

    return result.left(keyLen);
}

const mbedtls_cipher_info_t* info_from_cipherAlgo(std::string hname,std::string moudle)
{
    if (moudle == "CBC")
    {
        if (hname == "AES") return mbedtls_cipher_info_from_string("AES-128-CBC");
        if (hname == "AES-128") return mbedtls_cipher_info_from_string("AES-128-CBC");
        if (hname == "AES-192") return mbedtls_cipher_info_from_string("AES-192-CBC");
        if (hname == "AES-256") return mbedtls_cipher_info_from_string("AES-256-CBC");
    }
    return nullptr;
}
QByteArray cipher(const QByteArray& key, ALG_ID cipherAlgo, const QByteArray& IV, const std::vector<unsigned char>& raw)
{
    std::string cnam = (*AlgorithmInfo)[cipherAlgo].name;
    QByteArray output;

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_setup(&ctx, info_from_cipherAlgo(cnam,"CBC"));
    mbedtls_cipher_setkey(&ctx, (unsigned char*)key.data(), key.size() * 8, MBEDTLS_DECRYPT);//崩溃
    mbedtls_cipher_set_iv(&ctx, (unsigned char*)IV.data(), IV.size());
    //mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);//处理填充
    mbedtls_cipher_reset(&ctx);

    size_t out_len = 0;
    size_t finish_len = 0;
    size_t block_size = mbedtls_cipher_get_block_size(&ctx);
    output.resize(raw.size() + block_size);
    mbedtls_cipher_update(&ctx, raw.data(), raw.size(), reinterpret_cast<unsigned char*>(output.data()), &out_len);     // 支持分段加密
    
    mbedtls_cipher_finish(&ctx, reinterpret_cast<unsigned char*>(output.data()) + out_len, &finish_len);          // 自动补全 padding
    mbedtls_cipher_free(&ctx);
    output.resize(out_len + finish_len);
    return output;
}
std::vector<unsigned char> dataDecrypt(ALG_ID cipherAlgo, ALG_ID hashAlgo, const std::vector<unsigned char>& raw, const std::vector<unsigned char>& encKey, const std::vector<unsigned char>& iv, int rounds)
{
    std::string hname = ((*AlgorithmInfo)[hashAlgo].name == "HMAC") ? "SHA1" : (*AlgorithmInfo)[hashAlgo].name;
    
    int cipherAlgo_keyLength = (*AlgorithmInfo)[cipherAlgo].keyLength;
    int cipherAlgo_ivLength = (*AlgorithmInfo)[cipherAlgo].IVLength;

    QByteArray password(reinterpret_cast<const char*>(encKey.data()), static_cast<int>(encKey.size()));
    QByteArray salt(reinterpret_cast<const char*>(iv.data()), static_cast<int>(iv.size()));
    QByteArray ciphertext(reinterpret_cast<const char*>(iv.data()), static_cast<int>(iv.size()));

    QByteArray derived = pbkdf2(password, salt,rounds, cipherAlgo_keyLength + cipherAlgo_ivLength, hname);
    
    qDebug() << derived.toHex();
    QByteArray key = derived.left(cipherAlgo_keyLength);
    QByteArray iv2 = derived.mid(cipherAlgo_keyLength);
    //std::vector<unsigned char> cleartxt(decyrpt.cipher());
    key = key.left(cipherAlgo_keyLength);
    iv2 = iv2.left(cipherAlgo_ivLength);
    qDebug() << key.toHex();
    qDebug() << iv2.toHex();
    qDebug() << cipherAlgo;
    qDebug() << raw;

    QByteArray cleartxt = cipher(key, cipherAlgo, iv2, raw);
    qDebug() << cleartxt.toHex();
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(cleartxt.data()), reinterpret_cast<const uint8_t*>(cleartxt.data() + cleartxt.size()));;

}

std::vector<unsigned char> DPAPIHmac(ALG_ID hashAlgo,const std::vector<unsigned char>& pwdhash, const std::vector<unsigned char>& hmacSalt, const std::vector<unsigned char>& value)
{
    std::string hname = ((*AlgorithmInfo)[hashAlgo].name == "HMAC") ? "SHA1" : (*AlgorithmInfo)[hashAlgo].name;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string(hname.c_str());

    mbedtls_md_context_t ctx;

    int digestLen = mbedtls_md_get_size(md_info);
    std::vector<unsigned char> encKey(digestLen);
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1);

    mbedtls_md_hmac_starts(&ctx, pwdhash.data(), pwdhash.size());
    mbedtls_md_hmac_update(&ctx, hmacSalt.data(), hmacSalt.size());
    mbedtls_md_hmac_finish(&ctx, encKey.data());

    std::vector<unsigned char> rv(digestLen);
    mbedtls_md_hmac_reset(&ctx);
    mbedtls_md_hmac_starts(&ctx, encKey.data(), encKey.size());
    mbedtls_md_hmac_update(&ctx, value.data(), value.size());
    mbedtls_md_hmac_finish(&ctx, rv.data());

    mbedtls_md_free(&ctx);

    return rv;
}

std::vector<uint8_t> derivePwdHash(const std::vector<unsigned char>& pwdhash, const std::string& sid, const std::string& digest)
{
    QString qsid = QString::fromStdString(sid);
    qsid.append(QChar(0));
    std::u16string utf16le = qsid.toStdU16String();
    QByteArray sidBytes(reinterpret_cast<const char*>(utf16le.data()), static_cast<int>(utf16le.size() * sizeof(char16_t)));
    
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string(digest.c_str());
    std::vector<uint8_t> output(mbedtls_md_get_size(md_info));
    
    mbedtls_md_hmac(md_info, pwdhash.data(), pwdhash.size(), (const unsigned char*)sidBytes.constData(), sidBytes.size(), output.data());
    return output;
}
std::pair<std::string, std::map<std::string, key_type>> decrypt_lsa_key_nt6(const std::vector<unsigned char>& lsakey, const std::vector<unsigned char>& syskey)
{
    std::vector<unsigned char> dg(32);
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA-256, 1 = SHA-224

    // syskey 部分
    mbedtls_sha256_update(&ctx, syskey.data(), syskey.size());

    // 1000 次 lsakey[28:60]
    for (int i = 0; i < 1000; ++i)
    {
        mbedtls_sha256_update(&ctx, lsakey.data() + 28, 32);  // 60-28 = 32字节
    }
    mbedtls_sha256_finish(&ctx, dg.data());
    mbedtls_sha256_free(&ctx);  
    qDebug() << dg;

    size_t encrypted_len = lsakey.size() - 60;
    QByteArray keys(encrypted_len, 0);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, dg.data(), 256);  // 256 = AES-256

    for (size_t i = 0; i < encrypted_len; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT,
            lsakey.data() + 60 + i,
            reinterpret_cast<unsigned char*>(keys.data()) + i);
    }

    mbedtls_aes_free(&aes);
    qDebug() << keys;

    size_t size;
    std::memcpy(&size, keys.constData(), sizeof(size));
    qDebug() << size;

    keys = keys.mid(16, size);  // 取 keys[4:20]
    qDebug() << keys.toHex();

    QUuid uuid = uuidFromLittleEndian(keys.mid(4,16));
    QString currentkey = uuid.toString(QUuid::WithoutBraces).toLower();
    qDebug() << currentkey;

    uint32_t nb;
    std::memcpy(&nb, keys.data() + 24, 4);
    qDebug() << nb;

    int off = 28;
    std::map<std::string, key_type> kd;
    for (int i = 0; i < nb; i++)
    {
        QByteArray guidBytes(reinterpret_cast<const char*>(keys.data() + off), 16);
        QString g = uuidFromLittleEndian(guidBytes).toString(QUuid::WithoutBraces).toLower();
        uint32_t t, l;
        memcpy(&t, keys.data() + off + 16, 4);
        memcpy(&l, keys.data() + off + 20, 4);
        std::vector<uint8_t> k(keys.begin() + off + 24, keys.begin() + off + 24 + l);
        qDebug() << k;
        kd[g.toStdString()] = key_type{ t, k };
        off += 24 + l;
    }
    //qDebug() << kd;
    return { currentkey.toStdString(), kd};
}

std::vector<uint8_t> decrypt_lsa_secret(const std::vector<unsigned char>& secret, std::map<std::string, key_type>& lsa_keys)
{
    QByteArray guidBytes(reinterpret_cast<const char*>(secret.data() + 4), 16);  // 取 keys[4:20]
    QUuid uuid = uuidFromLittleEndian(guidBytes);
    QString keyid = uuid.toString(QUuid::WithoutBraces).toLower();
    qDebug() << keyid;

    if (lsa_keys.find(keyid.toStdString()) == lsa_keys.end())
        return {};
    uint32_t algo = 0;
    std::memcpy(&algo, secret.data() + 20, sizeof(uint32_t));
    qDebug() << algo;

    QByteArray dg(32,0);
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA-256, 1 = SHA-224

    // syskey 部分
    
    mbedtls_sha256_update(&ctx, lsa_keys[keyid.toStdString()].key.data(), lsa_keys[keyid.toStdString()].key.size());

    // 1000 次 lsakey[28:60]
    for (int i = 0; i < 1000; ++i)
    {
        mbedtls_sha256_update(&ctx, secret.data() + 28, 32);  // 60-28 = 32字节
    }
    mbedtls_sha256_finish(&ctx, reinterpret_cast<unsigned char*>(dg.data()));
    mbedtls_sha256_free(&ctx);
    qDebug() << dg.toHex();

    size_t encrypted_len = secret.size() - 60;
    QByteArray clear(encrypted_len,0);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, reinterpret_cast<unsigned char*>(dg.data()), 256);  // 256 = AES-256

    for (size_t i = 0; i < encrypted_len; i += 16)
    {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT,
            secret.data() + 60 + i,
            reinterpret_cast<unsigned char*>(clear.data()) + i);
    }

    mbedtls_aes_free(&aes);
    qDebug() << clear.toHex();

    uint32_t size = 0;
    std::memcpy(&size, clear.data(), sizeof(uint32_t));
    qDebug() << size;
    qDebug()<< std::vector<uint8_t>(clear.begin() + 16, clear.begin() + 16 + size);

    return std::vector<uint8_t>(clear.begin() + 16, clear.begin() + 16 + size);
}


std::vector<uint8_t> CryptSessionKeyXP(
    const std::vector<uint8_t>& masterkey,
    const std::vector<uint8_t>& nonce,
    ALG_ID hashAlgo,
    const std::vector<uint8_t>* entropy,
    const std::vector<uint8_t>* strongPassword,
    const std::vector<uint8_t>* verifBlob
) {
    std::vector<uint8_t> key = masterkey;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string((*AlgorithmInfo)[hashAlgo].name.c_str());

    const size_t hash_len = mbedtls_md_get_size(md_info);
    const size_t block_size = (*AlgorithmInfo)[hashAlgo].blockLength;


    if (masterkey.size() > 20) {
        uint8_t sha1_out[20];
        mbedtls_sha1(masterkey.data(), masterkey.size(), sha1_out);
        key.assign(sha1_out, sha1_out + 20);
    }

    // Pad masterkey with zeros
    if (masterkey.size() < block_size)
        key.resize(block_size, 0x00);

    // Compute ipad and opad
    std::vector<uint8_t> ipad(block_size);
    std::vector<uint8_t> opad(block_size);
    for (size_t i = 0; i < block_size; ++i) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5C;
    }

    // Inner digest: H(ipad || nonce)
    std::vector<uint8_t> tmp(hash_len);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, ipad.data(), ipad.size());
    mbedtls_md_update(&ctx, nonce.data(), nonce.size());
    mbedtls_md_finish(&ctx, tmp.data());

    // Outer digest: H(opad || inner || optional)
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, opad.data(), opad.size());
    mbedtls_md_update(&ctx, tmp.data(), tmp.size());

    if (entropy) {
        mbedtls_md_update(&ctx, entropy->data(), entropy->size());
    }

    if (strongPassword) {
        // SHA1(UTF-16LE encoding of strongPassword without nulls)
        std::u16string pw_utf16(reinterpret_cast<const char16_t*>(strongPassword->data()), strongPassword->size() / 2);
        while (!pw_utf16.empty() && pw_utf16.back() == u'\0') pw_utf16.pop_back();

        std::vector<uint8_t> utf16_bytes(pw_utf16.size() * 2);
        std::memcpy(utf16_bytes.data(), pw_utf16.data(), utf16_bytes.size());

        uint8_t sha1_pw[20];
        mbedtls_sha1(utf16_bytes.data(), utf16_bytes.size(), sha1_pw);
        mbedtls_md_update(&ctx, sha1_pw, 20);
    }
    else if (verifBlob) {
        mbedtls_md_update(&ctx, verifBlob->data(), verifBlob->size());
    }

    std::vector<uint8_t> result(hash_len);
    mbedtls_md_finish(&ctx, result.data());
    mbedtls_md_free(&ctx);
    return result;
}

std::vector<uint8_t> CryptSessionKeyWin7(
    const std::vector<uint8_t>& masterkey,
    const std::vector<uint8_t>& nonce,
    ALG_ID hashAlgo,
    const std::vector<uint8_t>* entropy,
    const std::vector<uint8_t>* strongPassword,
    const std::vector<uint8_t>* verifBlob)
{

    std::vector<uint8_t> key = masterkey;
    if (key.size() > 20 )
    {
        uint8_t hashed[20];
        mbedtls_sha1(key.data(), key.size(), hashed);
        key.assign(hashed, hashed + 20);
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string((*AlgorithmInfo)[hashAlgo].name.c_str());
    mbedtls_md_setup(&ctx, md_info, 1);

    mbedtls_md_hmac_starts(&ctx, key.data(), key.size());
    mbedtls_md_hmac_update(&ctx, nonce.data(), nonce.size());

    if (entropy)
    {
        mbedtls_md_hmac_update(&ctx, entropy->data(), entropy->size());
    }

    if (strongPassword)
    {
        std::vector<uint8_t> utf16le;
        for (char ch : *strongPassword)
        {
            if (ch != '\0')
            {
                utf16le.push_back(ch);
                utf16le.push_back(0x00);
            }
        }

        uint8_t sp_digest[64];
        mbedtls_sha512(utf16le.data(), utf16le.size(), sp_digest, 0);
        mbedtls_md_hmac_update(&ctx, sp_digest, 64);
    }
    else if (verifBlob)
    {
        mbedtls_md_hmac_update(&ctx, verifBlob->data(), verifBlob->size());
    }

    std::vector<uint8_t> result(mbedtls_md_get_size(md_info));
    mbedtls_md_hmac_finish(&ctx, result.data());

    mbedtls_md_free(&ctx);
    return result;
}

std::vector<uint8_t> CryptDeriveKey(std::vector<uint8_t> h, ALG_ID cipherAlgo, ALG_ID hashAlgo)
{
    size_t block_size = (*AlgorithmInfo)[hashAlgo].blockLength;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string((*AlgorithmInfo)[hashAlgo].name.c_str());

    if (h.size() > block_size)
    {
        std::vector<uint8_t> hash(mbedtls_md_get_size(md_info));
        mbedtls_md(md_info, h.data(), h.size(), hash.data());
        h = hash;
    }

    if (h.size() >= (*AlgorithmInfo)[cipherAlgo].keyLength)
        return std::vector<uint8_t>(h.begin(), h.begin() + (*AlgorithmInfo)[cipherAlgo].keyLength);

    h.resize(block_size, 0x00);

    std::vector<uint8_t> ipad(block_size);
    std::vector<uint8_t> opad(block_size);
    for (size_t i = 0; i < block_size; ++i)
    {
        ipad[i] = h[i] ^ 0x36;
        opad[i] = h[i] ^ 0x5c;
    }

    std::vector<uint8_t> k(mbedtls_md_get_size(md_info) * 2);
    mbedtls_md(md_info, ipad.data(), block_size, k.data());
    mbedtls_md(md_info, opad.data(), block_size, k.data() + mbedtls_md_get_size(md_info));

    //k = (*AlgorithmInfo)[cipherAlgo].do_fixup_key(k)
    if ((*AlgorithmInfo)[cipherAlgo].keyFixup)
    {
        (*AlgorithmInfo)[cipherAlgo].keyFixup(k.data(), k.size());
    }

    return k;
}
