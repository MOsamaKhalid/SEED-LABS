#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *dM = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *d = BN_new();

    // Initializing the values of n,e,M,d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&M, "4120746f702073656372657421"); // M = hex(A top secret!)
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // encrypt C= M^e mod n
    BN_mod_exp(C, M, e, n, ctx);
    

    //decrypt dM= C^d mod n
    BN_mod_exp(dM, C, d, n, ctx);

    if (BN_cmp(M,dM) == 0)
    {
        printf("\n Message Encrypted Successfully");
        printBN("\n Cipher Text C : ", C);
	printf("\n");
    }
    else
        printf("\n Encryption Failed");


    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(M);
    BN_clear_free(dM);
    BN_clear_free(C);
    BN_clear_free(d);

    return 0;
}
