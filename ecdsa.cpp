#include <iostream>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;

#define ECDSA_KEY NID_secp256k1

void ecdsaTest() {
    const unsigned char msg[] = "Hello World!";
    const int msg_len = sizeof(msg) - 1;

    EC_KEY* key = EC_KEY_new_by_curve_name(ECDSA_KEY);
    if (EC_KEY_generate_key(key) == 0) {
        cout << "ecdh generate_key error" << endl;
        return;
    }

    cout << ECDSA_size(key) << endl;
    unsigned char sign[72];
    unsigned int sign_len = 0;
    if (ECDSA_sign(0, msg, msg_len, sign, &sign_len, key) == 0) {
        cout << "ECDSA_sign error" << endl;
        return;
    }
    cout << sign_len << endl;
    for (int i = 0; i < sign_len; ++i) {
        printf("%02X", sign[i]);
    }
    printf("\n");

    if (ECDSA_verify(0, msg, msg_len, sign, sign_len, key) == 1) {
        cout << "ECDSA_verify success" << endl;
    } else {
        cout << "ECDSA_verify error" << endl;
    }
}