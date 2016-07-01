/* ssl/gm_enc.c */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */



#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/gmssl1.h>
#include <openssl/hmac.h>

/* convert error code to some byte can be encode */
int gmssl_alert_code(int code)
{
	return tls1_alert_code(code);
}


//add by andy TODO: 国密 数据扩展函数 P_hash
//TLS 在握手阶段使用两种不同的摘要算法 MD5 SHA-1,
//GmSSL 只使用SM3
// 计算方法 GM/T 0024-2014
// P_hash(secret,seed) = HMAC(secret,A(1) + seed ) +
//						 HMAC(secret,A(2) + seed ) +
//						 HMAC(secret,A(3) + seed ) +
//											...
static int gm1_P_hash(const EVP_MD *md,const unsigned char *sec,
					  int sec_len,
					  const void *seed1,int seed1_len,
					  const void *seed2,int seed2_len,
					  const void *seed3,int seed3_len,
					  const void *seed4,int seed4_len,
					  const void *seed5,int seed5_len,
					  unsigned char *out,int olen)
{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx,ctx_tmp,ctx_init;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;
	//TODO :
	
	chunk = EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	//对数据做HMAC
	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	EVP_MD_CTX_init(&ctx_init);
	EVP_MD_CTX_set_flags(&ctx_init,EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,sec,sec_len);
	if(!mac_key)
		goto err;
	if(!EVP_DigestSignInit(&ctx_init,NULL,md,NULL,mac_key))
		goto err;
	if(!EVP_MD_CTX_copy(&ctx,&ctx_init))
		goto err;
	if(seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
		goto err;
	if(seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
		goto err;
	if(seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
		goto err;
	if(seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
		goto err;
	if(seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
		goto err;
	if(!EVP_DigestSignFinal(&ctx,A1,&A1_len))
		goto err;

	for (;;) {
		if(!EVP_MD_CTX_copy_ex(&ctx,&ctx_init))
			goto err;
		if(!EVP_DigestSignUpdate(&ctx,A1,A1_len))
			goto err;
		if(olen > chunk && !EVP_MD_CTX_copy_ex(&ctx_tmp,&ctx))
			goto err;
		if(seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
			goto err;
		if(seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
			goto err;
		if(seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
			goto err;
		if(seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
			goto err;
		if(seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
			goto err;

		if(olen > chunk) {
			if(!EVP_DigestSignFinal(&ctx,out,&j))
				goto err;
			out += j;
			olen -= j;
			if(!EVP_DigestSignFinal(&ctx,A1,&A1_len))
				goto err;
		} else {
			if(!EVP_DigestSignFinal(&ctx,A1,&A1_len))
				goto err;
			memcpy(out,A1,olen);
			break;
		}

	}
	ret = 1;
err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	EVP_MD_CTX_cleanup(&ctx_init);
	OPENSSL_cleanse(A1,sizeof(A1));
	return ret;
}



//add by andy TODO:伪随机数算法 PRF 的计算需要使用sm3
// TLS 的 PRF 实现是两种摘要算法(MD5,SHA1) 的结果做异或
//计算方法 GM/T 0024-2014
// 密钥+标签+随机数 
// SM3的摘要长度是256比特(32)字节
// PRF(secret,label,seed) = P_SM3(secret,label+seed)
//
// arg1			       : gm1_get_algorithm2(SSL *s) to be write in gm_lib.c
// arg2,arg3   (seed1) : label "master_secret" . "client write key"  etc.
// arg4,arg5   (seed2) : client_random
// arg6,arg7   (seed3) : (may NULL) 
// arg8,arg9   (seed4) : server_random
// arg10,arg11 (seed5) : (may NULL)
// arg12,arg13 (per)   : input secret
// arg14,arg15,arg16   : output (key ,buff,buff_len)
//
static int gm1_PRF( long digest_mask,
					const void *seed1,int seed1_len,
					const void *seed2,int seed2_len,
					const void *seed3,int seed3_len,
					const void *seed4,int seed4_len,
					const void *seed5,int seed5_len,
					const unsigned char *sec,int slen,
					unsigned char *out1,unsigned char *out2,int olen)
{
	//TO BE Writing...
	int len,i,idx,count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret =0;

	/*计算摘要个数 ,国密 SM3的 index是6*/
	count = 0;
	for(idx = 0; ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if((m << TLS1_PRF_DGST_SHIFT) & digest_mask)
			count++;
	}
	if(!count) {
		/* Should never happen */
		SSLerr(SSL_F_TLS1_PRF,ERR_R_INTERNAL_ERROR);
		goto err;
	}

	len = slen / count; //分段
	if (count == 1)
		slen = 0;
	S1 = sec;
	memset(out1,0,olen);

	//多种摘要算法复合运算
	for(idx = 0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if((m << TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if(!md) {
				SSLerr(SSL_F_TLS1_PRF,SSL_R_UNSUPPORTED_DIGEST_TYPE);
				goto err;
			}
			if(!gm1_P_hash(md,S1,len + (slen & 1),
						seed1,seed1_len,
						seed2,seed2_len,
						seed3,seed3_len,
						seed4,seed4_len,
						seed5,seed5_len,
						out2,olen))
				goto err;
			S1 += len;
			for(i = 0 ; i < olen;i++) {
				out1[i] ^= out2[i];
			}
		}
	}
	ret = 1;
err:
	return ret;
}


/* --------------------------------------------- */
// add by andy :导出给meth结构的算法
// 生成主密钥的方法
// TODO:可能还要完善
/* --------------------------------------------- */
int gm1_generate_master_secret(SSL *s,unsigned char *out,unsigned char *p,int len)
{
	//TODO:
	unsigned char buff[SSL_MAX_MASTER_KEY_LENGTH];
	const void *co = NULL,*so = NULL;
	int col =0,sol = 0;

	gm1_PRF(ssl_get_algorithm2(s),
			TLS_MD_MASTER_SECRET_CONST,TLS_MD_MASTER_SECRET_CONST_SIZE,
			s->s3->client_random,SSL3_RANDOM_SIZE,
			co,col,
			s->s3->server_random,SSL3_RANDOM_SIZE,
			so,sol,
			p,len,
			s->session->master_key,buff,sizeof(buff));

	OPENSSL_cleanse(buff,sizeof(buff));

	fprintf(stderr,"gm1_generate_master()_secret complete.\n");

	return (SSL3_MASTER_SECRET_SIZE);
}



