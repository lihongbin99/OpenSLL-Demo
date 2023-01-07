#include <iostream>

#include <openssl/dh.h>
#include <openssl/pem.h>

using namespace std;

void dhTest() {
    DH* dh = DH_new();
    DH_generate_parameters_ex(dh, 512, DH_GENERATOR_5, NULL);
    DH_generate_key(dh);

    BIGNUM* p = 0;
    BIGNUM* g = 0;
    DH_get0_pqg(dh, (const BIGNUM**)&p, NULL, (const BIGNUM**)&g);

    DH* dh1 = DH_new();
    DH_set0_pqg(dh1, p, NULL, g);
    DH_generate_key(dh1);

    DH* dh2 = DH_new();
    DH_set0_pqg(dh2, p, NULL, g);
    DH_generate_key(dh2);

    unsigned char share_key1[64 * 1024];
    int share_key1_len = DH_compute_key(share_key1, DH_get0_pub_key(dh1), dh2);
    if (share_key1_len == -1) {
        cout << "DH_compute_key1 error" << endl;
        return;
    }
    printf("shared_key1(%d):\n", share_key1_len);
    for (int i = 0; i < share_key1_len; ++i) {
        printf("%02X", share_key1[i]);
    }
    printf("\n");

    unsigned char share_key2[64 * 1024];
    int share_key2_len = DH_compute_key(share_key2, DH_get0_pub_key(dh2), dh1);
    if (share_key2_len == -1) {
        cout << "DH_compute_key2 error" << endl;
        return;
    }
    printf("shared_key2(%d):\n", share_key2_len);
    for (int i = 0; i < share_key2_len; ++i) {
        printf("%02X", share_key2[i]);
    }
    printf("\n");

    // 释放内存
    DH_free(dh1);
    DH_free(dh2);
}
