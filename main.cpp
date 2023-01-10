#include <iostream>

#include "md.cpp"
#include "sha.cpp"
#include "aes.cpp"
#include "rsa.cpp"
#include "dh.cpp"
#include "dsa.cpp"
#include "ecdh.cpp"
#include "ecdsa.cpp"
#include "x25519.cpp"

#include <openssl/err.h>

using namespace std;

int main() {
    // mdTest();
    // shaTest();
    // aesTest();
    // rsaTest();
    // dhTest();
    // dsaTest();
    // ecdhTest();
    // ecdsaTest();
    x25519Test();
}
