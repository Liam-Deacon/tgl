/* 
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Ben Wiederhake 2015
*/

#include "../config.h"

#ifndef TGL_AVOID_OPENSSL

//#include <stddef.h> /* NULL */

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "bn.h"
#include "meta.h"
#include "rsa_pem.h"

TGLC_WRAPPER_ASSOC(rsa,RSA)

// TODO: Refactor crucial struct-identity into its own header.
TGLC_WRAPPER_ASSOC(bn,BIGNUM)

TGLC_rsa *TGLC_rsa_new (unsigned long e, int n_bytes, const unsigned char *n) {
  RSA *ret = RSA_new ();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ret->e = unwrap_bn (TGLC_bn_new ());
  TGLC_bn_set_word (wrap_bn (ret->e), e);
  ret->n = unwrap_bn (TGLC_bn_bin2bn (n, n_bytes, NULL));
#else
  BIGNUM *e_bn = unwrap_bn (TGLC_bn_new ());
  BIGNUM *n_bn = unwrap_bn (TGLC_bn_bin2bn (n, n_bytes, NULL));
  TGLC_bn_set_word (wrap_bn (e_bn), e);
  if (!RSA_set0_key (ret, n_bn, e_bn, NULL)) {
    TGLC_bn_free (wrap_bn (e_bn));
    TGLC_bn_free (wrap_bn (n_bn));
    RSA_free (ret);
    return NULL;
  }
#endif
  return wrap_rsa (ret);
}

static BIGNUM *TGLC_rsa_get_n (RSA *key) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  return key->n;
#else
  const BIGNUM *n = NULL;
  RSA_get0_key (key, &n, NULL, NULL);
  return (BIGNUM *)n;
#endif
}

static BIGNUM *TGLC_rsa_get_e (RSA *key) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  return key->e;
#else
  const BIGNUM *e = NULL;
  RSA_get0_key (key, NULL, &e, NULL);
  return (BIGNUM *)e;
#endif
}

#define RSA_GETTER(M)                                                          \
  TGLC_bn *TGLC_rsa_ ## M (TGLC_rsa *key) {                                    \
    return wrap_bn (TGLC_rsa_get_ ## M (unwrap_rsa (key)));                    \
  }                                                                            \

RSA_GETTER(n);
RSA_GETTER(e);

void TGLC_rsa_free (TGLC_rsa *p) {
  RSA_free (unwrap_rsa (p));
}

TGLC_rsa *TGLC_pem_read_RSAPublicKey (FILE *fp) {
  return wrap_rsa (PEM_read_RSAPublicKey (fp, NULL, NULL, NULL));
}

#endif
