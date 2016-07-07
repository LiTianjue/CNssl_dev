#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define SM2_KEY_FILE    "/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/client.pem"

#define SM2_CERT_FILE    "/home/andy/GitHub/WORK/gmssl_dev/gmssl_dev/Cert/SM2_Cert/client/client.cer"

int test_sm2_evp(int verbose );

void api_init()
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}



//从文件读取sm2的秘钥
EVP_PKEY *load_sm2_key_from_file(const char *file)
{

    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    key = BIO_new(BIO_s_file());
    if(key == NULL) {
        return NULL;
    }

    if(BIO_read_filename(key,file) <=0) {
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(key,NULL,NULL,NULL);

	//EC_GROUP_new_by_curve_name(1);

    if(key != NULL)
        BIO_free(key);
    if(pkey == NULL){
        printf("unable to load %s\n",file);
    }

    return pkey;
}

// test sm2sign
int test_sm2_evp_pkey_sign(EVP_PKEY *pkey,int do_sm2,int verbose)
{
    int ret = 0;
    EVP_PKEY_CTX *pkctx = NULL;
    int type = do_sm2 ? NID_sm_scheme : NID_secg_scheme;
    unsigned char dgst[EVP_MAX_MD_SIZE] = "hello world";
    size_t dgstlen;
    unsigned char sig[256];
    size_t siglen;

    if(!(pkctx = EVP_PKEY_CTX_new(pkey,NULL))) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }

    //签名
    if(!EVP_PKEY_sign_init(pkctx) ){
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }

    if(!EVP_PKEY_CTX_set_ec_sign_type(pkctx,type)) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }

    dgstlen = 32;
    bzero(sig,sizeof(sig));
    siglen = sizeof(sig);

    if(!EVP_PKEY_sign(pkctx,sig,&siglen,dgst,dgstlen)) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }

    if(verbose > 1) {
        size_t i;
        printf("signature (%zu bytes = ",siglen);
        for(i = 0;i < siglen;i++) {
            printf("%02X",sig[i]);
        }
        printf("\n");
    }

    //验签
    if(!EVP_PKEY_verify_init(pkctx)) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }
    if(!EVP_PKEY_CTX_set_ec_sign_type(pkctx,type)) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }
    if(EVP_PKEY_verify(pkctx,sig,siglen,dgst,dgstlen) != SM2_VERIFY_SUCCESS) {
        fprintf(stderr,"error :%s %d\n",__FILE__,__LINE__);
        goto end;
    }

    if(verbose) {
        printf("%s(%s) passed \n",__FUNCTION__,OBJ_nid2sn(type));
    }

    ret = 1;
end:
       EVP_PKEY_CTX_free(pkctx);
       return ret;
}


int test_sm2_evp(int verbose )
{
    api_init();

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    BIO *out = NULL;

    out = BIO_new_fp(stderr,BIO_NOCLOSE);

    if(!(pkey = load_sm2_key_from_file(SM2_KEY_FILE)))
    {
        goto err;
    }

    if(!test_sm2_evp_pkey_sign(pkey,1,verbose))
    {
        goto err;
    }

err:
    return 0;
}



int test_sm2_cert_usage(X509 *x)
{
	int id,ret;
	id = X509_PURPOSE_OCSP_HELPER;

	ret = X509_check_purpose(x,id,0);
	if(ret == 1)
	{
		printf("purpose check ok !\n");
	} else {
		printf("purpose check failed!\n");
	}


	return 0;
}

int test_sm2_check_private_key(X509 *x,EVP_PKEY *pkey)
{
	//EVP_PKEY *pkey = load_sm2_key_from_file(SM2_KEY_FILE);

	int ret = 0;
	ret = X509_check_private_key(x,pkey);
	if(ret != 1)
	{
		printf("Check SM2 private Fail!!!\\n");
	} else {
		printf("Check SM2 private Key OK \n");
	}

	return ret;
	
}



int test_sm2_x509()
{
	X509	*x;
	FILE	*fp;
	unsigned char buf[5000],*p;
	int len,ret;
	BIO *b;
	
	fp = fopen(SM2_CERT_FILE,"rb");
	if(!fp)
		return -1;

	len = fread(buf,1,5000,fp);
	fclose(fp);

	p =  buf;
	x = X509_new();
	d2i_X509(&x,(const unsigned char **)&p,len);
	b = BIO_new(BIO_s_file());
	BIO_set_fp(b,stdout,BIO_NOCLOSE);
	//ret = X509_print(b,x);
	
	EVP_PKEY *pkey = load_sm2_key_from_file(SM2_KEY_FILE);

	test_sm2_cert_usage(x);
	test_sm2_check_private_key(x,pkey);
	
	BIO_free(b);
	X509_free(x);

	return 0;
}
