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

	BIGNUM *Sig = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *VSig = BN_new();
	
	//Initilizing values of n,e,m,sig
	BN_hex2bn(&n, "D753A40451F899A616484B6727AA9349D039ED0CB0B00087F1672886858C8E63DABCB14038E2D3F5ECA50518B83D3EC5991732EC188CFAF10CA6642185CB071034B052882B1F689BD2B18F12B0B3D2E7881F1FEF387754535F80793F2E1AAAA81E4B2B0DABB763B935B77D14BC594BDF514AD2A1E20CE29082876AAEEAD764D69855E8FDAF1A506C54BC11F2FD4AF29DBB7F0EF4D5BE8E16891255D8C07134EEF6DC2DECC48725868DD821E4B04D0C89DC392617DDF6D79485D80421709D6F6FFF5CBA19E145CB5657287E1C0D4157AAB7B827BBB1E4FA2AEF2123751AAD2D9B86358C9C77B573ADD8942DE4F30C9DEEC14E627E17C0719E2CDEF1F910281933");

	BN_hex2bn(&e, "010001");

	BN_hex2bn(&M, "84233b332caa1af36983d22a997cbdd61c3fd11bcf4664d2963afb827a760c98");
	
	BN_hex2bn(&Sig, "b68a5cd943d6c888ad1e8a6dea2e46be55bfa31e828ea7ba6c76e9ccaec678650af9cf5fcf3133f4d3c3ff97e955e0ceec67f5b5186d4cc59c8b0af14dcb21f82786da39213f85a3aebed0fd96c14f7e50acc126d9e8cdb01ce5a39d9dc15f0ad79f662243e778c6632e71496e37581d004b04cb91fa7d0fec3e84014a05707a430db3cccccd7042fd5169327b88ed372b4bebaf486d1e315160c5d172e06dc97409b0454a874664df8fdca7c85897362972819be7a412f8aec3ee784912ad770ee7368213bca4cd5d79fbb04c8612e3953812e73f3c0cac79ef25d7810b1f5faac93c17cdd2c0cca7aeffd9e3ccc039923d30d32bce83c3992e3f43b593ebfd"); 

	// decrypt VSig = Sig^e mod n
	BN_mod_exp(VSig, Sig, e, n, ctx);

	// Truncate hash value to 256 bits
	BN_mask_bits(VSig, 256);

	 //veryfing the signature
    if (BN_cmp(M,VSig) == 0)
    {
        printf("\nSignature Verified Successfully");
        printBN("\n Message Hash :", M);
        printBN("\n Signature of Message  : ", VSig);
        printf("\n");
	

    }
    else
        printf("\n Sigature is Invalid");


    BN_clear_free(Sig);
    BN_clear_free(e);    
    BN_clear_free(n);
    BN_clear_free(M);
    BN_clear_free(VSig);
 
    return 0;
}

	
