#include <iostream>

#include <openssl/dsa.h>
#include <openssl/pem.h>

using namespace std;

#define DSA_key_len 1024

void dsaTest() {
    const unsigned char msg[] = "Hello World!";
    const int msg_len = sizeof(msg) - 1;

    DSA* dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, DSA_key_len, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);

    // const BIGNUM* p = DSA_get0_p(dsa);
    // const BIGNUM* q = DSA_get0_q(dsa);
    // const BIGNUM* g = DSA_get0_g(dsa);
    // const BIGNUM* pub = DSA_get0_pub_key(dsa);
    // const BIGNUM* pri = DSA_get0_priv_key(dsa);
    // char* pc = BN_bn2hex(p);
    // cout << "p(" << strlen(pc) / 2 << "): \n" << pc << "\n" << endl;
    // char* qc = BN_bn2hex(q);
    // cout << "q(" << strlen(qc) / 2 << "): \n" << qc << "\n" << endl;
    // char* gc = BN_bn2hex(g);
    // cout << "g(" << strlen(gc) / 2 << "): \n" << gc << "\n" << endl;
    // char* pubc = BN_bn2hex(pub);
    // cout << "pub(" << strlen(pubc) / 2 << "): \n" << pubc << "\n" << endl;
    // char* pric = BN_bn2hex(pri);
    // cout << "pri(" << strlen(pric) / 2 << "): \n" << pric << "\n" << endl;

    int len = DSA_size(dsa);
    cout << "DSA_size: " << len << endl;

    unsigned char sign[64 * 1024];
    unsigned int sign_len = 0;
    if (DSA_sign(0, msg, msg_len, sign, &sign_len, dsa) == 0) {
        cout << "DSA_sign error" << endl;
        return;
    }
    cout << "sign_len: " << sign_len << endl;
    for (int i = 0; i < sign_len; ++i) {
        printf("%02X", sign[i]);
    }
    printf("\n");

    if (DSA_verify(0, msg, msg_len, sign, sign_len, dsa) == 0) {
        cout << "dsa verify error" << endl;
    } else {
        cout << "dsa verify success" << endl;
    }

}
