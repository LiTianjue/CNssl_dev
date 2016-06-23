/* ssl/gm_srvr.c */
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
#include <openssl/x509.h>
#include <openssl/gmssl1.h>

static const SSL_METHOD *gm1_get_server_method(int ver)
{
	if (ver == GM1_VERSION) {
		return GMSSLv1_server_method();
	}
	return NULL;
}

IMPLEMENT_gm1_meth_func(GMSSLv1_server_method,
			ssl3_accept,ssl_undefined_function,
			gm1_get_server_method)


	/* --------------------------------------------- */
	/* 服务端方法宏展开应该是*/
	/*
	   const SSL_METHOD *GMSSLv1_server_method(void) {
	   static const GMSSLv1_server_method_data={
	   0x0101,		//协议版本号	GMSSLv1	0x0101
	   tls1_new,	// new 一个 SSL
	   tls1_clear,	// 清除	SSL
	   tls1_free,	// 释放
	   ssl3_accept, // 
	   ssl_undefined_function,	//服务端不用定义connect 方法
	   ssl3_read,	// 读
	   ssl3_peek,	// 试读
	   ssl3_write,	// 写
	   ssl3_shutdown,	// 关闭连接
	   ssl3_renegotiate,	//重新协商
	   ssl3_renegotiate_check,	//重新协商检查
	   ssl3_get_message,		// 从原始握手数据包中截取数据
	   ssl3_read_bytes,		// 读 bytes
	   ssl3_write_bytes,		// 写 bytes
	   ssl3_dispatch_alert,		// 报警
	   ssl3_ctrl,				//控制？
	   ssl3_ctx_ctrl,			// ctx 控制？
	   gm1_get_cipher_by_char,	// 获取加密套件			需要重写
	   gm1_put_cipher_by_char,	// 设置加密套件			需要重写
	   ssl3_pending,			// pending
	   gm1_num_ciphers,		// 加密套件个数
	   gm1_get_cipher,		// 获取加密套件				客户端调用?
	   tls1_get_method,		//获取method ，获取自己？
	   tls1_default_timeout,		// 默认超时时间
	   &GMSSLv1_enc_data,		// 一系列的加密运算
	   ssl_undefined_void_function,	//					ssl_version
	   ssl3_callback_ctrl,		// 回调个啥？
	   ssl3_ctx_callback_ctrl,		//回调个啥？
	   };
	   return &TLSv1_1_method_data;
	   }
	   */



	/* -------------------------------------------- */
