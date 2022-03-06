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

    BIGNUM *M1 = BN_new();
    BIGNUM *M2 = BN_new();
    BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *Sig1 = BN_new();
    BIGNUM *Sig2 = BN_new();
    BIGNUM *VSig1 = BN_new();
    BIGNUM *VSig2 = BN_new();

    // Initilizing values of M1,M2,d,n,e
	BN_hex2bn(&M1, "49206f776520796f75202432303030"); // M = hex(I owe you $2000)
    BN_hex2bn(&M2, "49206f776520796f75202433303030"); // M = hex(I owe you $3000)    
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");    

    // encrypt Sig1 = M1^d mod n
    BN_mod_exp(Sig1, M1, d, n, ctx);
    printf("\n M1: I owe you $2000");
    // dcrypt VSig1 = Sig1^e mod n
    BN_mod_exp(VSig1, Sig1, e, n, ctx);
    
    //veryfing the signature of M1
    if (BN_cmp(M1,VSig1) == 0)
    {
        printf("\n Message1 Signed Successfully");
        printBN("\n Signature of Message 1 : ", Sig1);
	printf("\n");
    }
    else
        printf("\n Message Signed Failed");

    // encrypt Sig2= M2^d mod n
    BN_mod_exp(Sig2, M2, d, n, ctx);
    printf("\n M2: I owe you $3000");
    // dcrypt VSig2 = Sig2^e mod n
    BN_mod_exp(VSig2, Sig2, e, n, ctx);
     
    //veryfing the signature of M2
    if (BN_cmp(M2,VSig2) == 0)
    {
        printf("\n Message2 Signed Successfully");
        printBN("\n Signature of Message 2 : ", Sig2);
	printf("\n");
    }
    else
        printf("\n Message Signed Failed");


    BN_clear_free(M1);
    BN_clear_free(M2);    
    BN_clear_free(d);
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(Sig1);
    BN_clear_free(Sig2);
    BN_clear_free(VSig1);
    BN_clear_free(VSig2);

    return 0;
}
