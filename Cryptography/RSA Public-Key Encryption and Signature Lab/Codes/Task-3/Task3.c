#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main() 
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *C = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
 	BIGNUM *M = BN_new();

	// Initializing the values of c,d,n
	BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
 	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	
	//decrypt dM= C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    printBN("\n Message M : ", M);
    printf("\n");

    BN_clear_free(C);
    BN_clear_free(d);
    BN_clear_free(n);
    BN_clear_free(M);

    return 0;
}
