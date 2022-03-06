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

	BIGNUM *M = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *Sig = BN_new();
	BIGNUM *VSig = BN_new();

	// Initilizing values of M,n,e,1sig 
	BN_hex2bn(&M, "4c61756e63682061206d697373696c652e"); //M = hex(Launch a missile.)
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001"); 
    BN_hex2bn(&Sig, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");


    // decrypt VSig= Sig^e mod n
    BN_mod_exp(VSig, Sig, e, n, ctx);

    //veryfing the signature of M
    if (BN_cmp(M,VSig) == 0)
    {
        printf("\n Message received is from Alice");

        printBN("\n Message : ", M);
        printBN("\n Signature of Message 1 : ", VSig);
	printf("\n");

    }
    else
    {   printf("\n Signatue Verification Failed");
        printf("\n Message received is not from Alice");
	    printBN("\n Message : ", VSig);
	    printf("\n");
    }


    BN_clear_free(M);
    BN_clear_free(n);    
    BN_clear_free(e);
    BN_clear_free(Sig);
    BN_clear_free(VSig);
 
    return 0;
}
