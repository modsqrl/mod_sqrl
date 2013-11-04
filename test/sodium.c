
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sodium/core.h"
#include "sodium/crypto_sign.h"

int main()
{
    char *m;
    unsigned char *pk, *sk, *sm;
    unsigned long long mlen, smlen;
    int rv;

    /* Initialize libsodium */
    rv = sodium_init();
    if(rv) {
        fprintf(stderr, "Error initializing libsodium: %d", rv);
        return rv;
    }

    /* Allocate keys */
    pk = malloc(crypto_sign_PUBLICKEYBYTES * sizeof(unsigned char *));
    sk = malloc(crypto_sign_SECRETKEYBYTES * sizeof(unsigned char *));

    /* Generate the private and public keys */
    rv = crypto_sign_keypair(pk, sk);
    if(rv) {
        fprintf(stderr, "Error generating keys: %d", rv);
        return rv;
    }

    /* Sign a message */
    m = "This is a test.";
    mlen = strlen(m);
    sm = malloc((crypto_sign_BYTES + mlen) * sizeof(unsigned char *));
    rv = crypto_sign(sm, &smlen, (unsigned char *)m, mlen, sk);
    if(rv) {
        fprintf(stderr, "Error signing the message: %d", rv);
        return rv;
    }

    /* Verify signature */
    m = malloc(smlen * sizeof(unsigned char *) + 1);
    rv = crypto_sign_open((unsigned char *)m, &mlen, sm, smlen, pk);
    if(rv) {
        fprintf(stderr, "Error verifying the message: %d", rv);
        return rv;
    }

    m[mlen] = '\0';
    printf("Verificatin successful: %s\n", m);

    /* Cleanup */
    free(m);
    free(sm);
    free(sk);
    free(pk);

    return 0;
}

