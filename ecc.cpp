#include <iostream>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/err.h>

void eccTest() {
    ERR_load_CRYPTO_strings();

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, group);

    int i = 1 == 1 ? 1 : 0;

    EC_KEY_generate_key(key);

    const EC_POINT* pubkey = EC_KEY_get0_public_key(key);
    const BIGNUM *prikey = EC_KEY_get0_private_key(key);

    unsigned char* pubkey_buf = new unsigned char[64 * 1024];
    unsigned char* prikey_buf = new unsigned char[64 * 1024];
    int pubkey_len = i2o_ECPublicKey(key, &pubkey_buf);
    int prikey_len = i2d_ECPrivateKey(key, &prikey_buf);

    EC_POINT* ciphertext = EC_POINT_new(group);

    BIGNUM* plaintext = BN_new();
    BN_hex2bn(&plaintext, "1234567890ABCDEF");

    EC_POINT_mul(group, ciphertext, plaintext, NULL, NULL, NULL);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(group, ciphertext, NULL, ciphertext, prikey, ctx);

    BIGNUM *decrypted = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, ciphertext, decrypted, NULL, ctx);

    std::cout << "Decrypted: " << BN_bn2hex(decrypted) << std::endl;

    BN_CTX_free(ctx);
    BN_free(plaintext);
    BN_free(decrypted);
    EC_POINT_free(ciphertext);
    EC_KEY_free(key);
    EC_GROUP_free(group);
}
