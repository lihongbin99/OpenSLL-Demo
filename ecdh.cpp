#include <iostream>

#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/obj_mac.h>

using namespace std;

#define ECDH_KEY NID_secp256k1

void ecdhTest() {
    // 生成EC密钥对
    EC_KEY* key1 = EC_KEY_new_by_curve_name(ECDH_KEY);
    if (EC_KEY_generate_key(key1) == 0) {
        cout << "ecdh generate_key1 error" << endl;
        return;
    }

    EC_KEY* key2 = EC_KEY_new_by_curve_name(ECDH_KEY);
    if (EC_KEY_generate_key(key2) == 0) {
        cout << "ecdh generate_key2 error" << endl;
        return;
    }

    // BN_CTX* ctx;
    // ctx = BN_CTX_new();
    // char* pub1c = EC_POINT_point2hex(EC_KEY_get0_group(key1), EC_KEY_get0_public_key(key1), POINT_CONVERSION_UNCOMPRESSED, ctx);
    // cout << "pub1(" << strlen(pub1c) << "): \n" << pub1c << "\n" << endl;
    // // ctx = BN_CTX_new();
    // char* pub2c = EC_POINT_point2hex(EC_KEY_get0_group(key2), EC_KEY_get0_public_key(key2), POINT_CONVERSION_UNCOMPRESSED, ctx);
    // cout << "pub2(" << strlen(pub2c) << "): \n" << pub2c << "\n" << endl;

    unsigned char shared_key1[32];
    if (ECDH_compute_key(shared_key1, sizeof(shared_key1), EC_KEY_get0_public_key(key2), key1, NULL) == 0) {
        cout << "ecdh compute_key1 error" << endl;
        return;
    }
    printf("shared_key1: ");
    for (int i = 0; i < sizeof(shared_key1); ++i) {
        printf("%02X", shared_key1[i]);
    }
    printf("\n");

    unsigned char shared_key2[32];
    if (ECDH_compute_key(shared_key2, sizeof(shared_key2), EC_KEY_get0_public_key(key1), key2, NULL) == 0) {
        cout << "ecdh compute_key2 error" << endl;
        return;
    }
    printf("shared_key2: ");
    for (int i = 0; i < sizeof(shared_key2); ++i) {
        printf("%02X", shared_key2[i]);
    }
    printf("\n");

    // 释放内存
    EC_KEY_free(key1);
    EC_KEY_free(key2);
}
