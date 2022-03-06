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
		
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *phiOfN = BN_new();
	BIGNUM *p_minus_one = BN_new(); //p-1
	BIGNUM *q_minus_one = BN_new(); //q-1
	BIGNUM *e = BN_new();
	BIGNUM *rPrime = BN_new(); //Relatively Prime
	BIGNUM *d = BN_new();
	BIGNUM *one = BN_new(); //1

	// Initializing the values of p,q,e,1
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_dec2bn(&one, "1");
	
	// Calculate n=p*q
	BN_mul(n, p, q, ctx);

	// Calculate the phiOfN = (p - 1)*(q - 1)
	BN_sub(p_minus_one, p, one); 
	BN_sub(q_minus_one, q, one); 
	BN_mul(phiOfN, p_minus_one, q_minus_one, ctx); 

	// check if gcd(phiOfN,e)=1
    BN_gcd(rPrime, phiOfN, e, ctx);
    if (!BN_is_one(rPrime))
    {
        printf("\nError: e and phiOfN are not relatively prime to each other ");
        exit(0);
    }

	// Calculate the vaule of d : d*e mod phiOfN = 1
	BN_mod_inverse(d, e, phiOfN, ctx);

	printBN("\nPrivate Key d : ", d);
	printf("\n");


	BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(n);
    BN_clear_free(phiOfN);
    BN_clear_free(p_minus_one);
    BN_clear_free(q_minus_one);
    BN_clear_free(e);
    BN_clear_free(rPrime);
    BN_clear_free(d);
    BN_clear_free(one);
};
