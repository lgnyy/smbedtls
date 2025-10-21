/*
 *  Public Key abstraction layer: wrapper functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk_internal.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedtls/rsa.h"
#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#endif

#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_SM2_C)
#include "mbedtls/sm2.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <limits.h>
#include <stdint.h>

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}
#endif

#if defined(MBEDTLS_RSA_C)
static int rsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA ||
            type == MBEDTLS_PK_RSASSA_PSS );
}

static size_t rsa_get_bitlen( const void *ctx )
{
    return( 8 * ((const mbedtls_rsa_context *) ctx)->len );
}

static int rsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    int ret;

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    if( sig_len < ((mbedtls_rsa_context *) ctx)->len )
        return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

    if( ( ret = mbedtls_rsa_pkcs1_verify( (mbedtls_rsa_context *) ctx, NULL, NULL,
                                  MBEDTLS_RSA_PUBLIC, md_alg,
                                  (unsigned int) hash_len, hash, sig ) ) != 0 )
        return( ret );

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if( sig_len > ((mbedtls_rsa_context *) ctx)->len )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int rsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = ((mbedtls_rsa_context *) ctx)->len;

    return( mbedtls_rsa_pkcs1_sign( (mbedtls_rsa_context *) ctx, f_rng, p_rng, MBEDTLS_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ilen != ((mbedtls_rsa_context *) ctx)->len )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( mbedtls_rsa_pkcs1_decrypt( (mbedtls_rsa_context *) ctx, f_rng, p_rng,
                MBEDTLS_RSA_PRIVATE, olen, input, output, osize ) );
}

static int rsa_encrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    *olen = ((mbedtls_rsa_context *) ctx)->len;

    if( *olen > osize )
        return( MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE );

    return( mbedtls_rsa_pkcs1_encrypt( (mbedtls_rsa_context *) ctx,
                f_rng, p_rng, MBEDTLS_RSA_PUBLIC, ilen, input, output ) );
}

static int rsa_check_pair_wrap( const void *pub, const void *prv )
{
    return( mbedtls_rsa_check_pub_priv( (const mbedtls_rsa_context *) pub,
                                (const mbedtls_rsa_context *) prv ) );
}

static void *rsa_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_context ) );

    if( ctx != NULL )
        mbedtls_rsa_init( (mbedtls_rsa_context *) ctx, 0, 0 );

    return( ctx );
}

static void rsa_free_wrap( void *ctx )
{
    mbedtls_rsa_free( (mbedtls_rsa_context *) ctx );
    mbedtls_free( ctx );
}

static void rsa_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((mbedtls_rsa_context *) ctx)->N );

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((mbedtls_rsa_context *) ctx)->E );
}

const mbedtls_pk_info_t mbedtls_rsa_info = {
    MBEDTLS_PK_RSA,
    "RSA",
    rsa_get_bitlen,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_sign_wrap,
    rsa_decrypt_wrap,
    rsa_encrypt_wrap,
    rsa_check_pair_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
    rsa_debug,
};
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * Generic EC key
 */
static int eckey_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECKEY ||
            type == MBEDTLS_PK_ECKEY_DH ||
            type == MBEDTLS_PK_ECDSA );
}

static size_t eckey_get_bitlen( const void *ctx )
{
    return( ((mbedtls_ecp_keypair *) ctx)->grp.pbits );
}

#if defined(MBEDTLS_ECDSA_C)
/* Forward declarations */
static int ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );

static int ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static int eckey_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init( &ecdsa );

    if( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    mbedtls_ecdsa_free( &ecdsa );

    return( ret );
}

static int eckey_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init( &ecdsa );

    if( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_sign_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len,
                               f_rng, p_rng );

    mbedtls_ecdsa_free( &ecdsa );

    return( ret );
}

#endif /* MBEDTLS_ECDSA_C */

static int eckey_check_pair( const void *pub, const void *prv )
{
    return( mbedtls_ecp_check_pub_priv( (const mbedtls_ecp_keypair *) pub,
                                (const mbedtls_ecp_keypair *) prv ) );
}

static void *eckey_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );

    if( ctx != NULL )
        mbedtls_ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    mbedtls_ecp_keypair_free( (mbedtls_ecp_keypair *) ctx );
    mbedtls_free( ctx );
}

static void eckey_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}

const mbedtls_pk_info_t mbedtls_eckey_info = {
    MBEDTLS_PK_ECKEY,
    "EC",
    eckey_get_bitlen,
    eckey_can_do,
#if defined(MBEDTLS_ECDSA_C)
    eckey_verify_wrap,
    eckey_sign_wrap,
#else
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,
    eckey_free_wrap,
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECKEY ||
            type == MBEDTLS_PK_ECKEY_DH );
}

const mbedtls_pk_info_t mbedtls_eckeydh_info = {
    MBEDTLS_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_bitlen,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
    eckey_debug,            /* Same underlying key structure */
};
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_ECDSA_C)
static int ecdsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECDSA );
}

static int ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature( (mbedtls_ecdsa_context *) ctx,
                                hash, hash_len, sig, sig_len );

    if( ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( ret );
}

static int ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_ecdsa_write_signature( (mbedtls_ecdsa_context *) ctx,
                md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng ) );
}

static void *ecdsa_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecdsa_context ) );

    if( ctx != NULL )
        mbedtls_ecdsa_init( (mbedtls_ecdsa_context *) ctx );

    return( ctx );
}

static void ecdsa_free_wrap( void *ctx )
{
    mbedtls_ecdsa_free( (mbedtls_ecdsa_context *) ctx );
    mbedtls_free( ctx );
}

const mbedtls_pk_info_t mbedtls_ecdsa_info = {
    MBEDTLS_PK_ECDSA,
    "ECDSA",
    eckey_get_bitlen,     /* Compatible key structures */
    ecdsa_can_do,
    ecdsa_verify_wrap,
    ecdsa_sign_wrap,
    NULL,
    NULL,
    eckey_check_pair,   /* Compatible key structures */
    ecdsa_alloc_wrap,
    ecdsa_free_wrap,
    eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_SM2_C)

static int sm2_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_SM2 );
}

#if defined(MBEDTLS_GM_PROTO_SSL1_1_LOG_ENABLE)
static void print_hex(const char* tip, const unsigned char* data, int datal)
{
    int i;
    printf("[%s][%d(0x%x)]:", tip, datal, datal);
    for (i = 0; i < datal; i++)
    {
        printf("%02X", data[i]);
    }
    printf("\n");
}
#endif

static int sm2_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    if( hash_len != mbedtls_md_get_size( mbedtls_md_info_from_type( md_alg ) )
            || sig_len <= 0 )
        return( MBEDTLS_ERR_ECP_VERIFY_FAILED );

#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
    unsigned char rs[64+16];
    if ((sig[0] == 0x30) && (sig[1] == sig_len - 2) && (sig[2] == 0x02)) {
#if 0
        unsigned char rlen = sig[3];
        unsigned char slen = sig[4+rlen+1];
        memset(rs, 0, 64);
        if (rlen > 32) {
            memcpy(rs, sig + 5, 32);
        }
        else {
            memcpy(rs + 32-rlen, sig + 4, rlen);
        }
        if (slen > 32) {
            memcpy(rs + 32, sig + 4 + rlen + 3, 32);
        }
        else {
            memcpy(rs - slen, sig + 4 + rlen + 2, slen);
        }
#else
        int ret;
        size_t len;// , r_len, s_len;
        mbedtls_mpi r, s;
        unsigned char* p = (unsigned char*)sig;
        const unsigned char* end2 = sig + sig_len;

        if ((ret = mbedtls_asn1_get_tag(&p, end2, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
        {
            return(MBEDTLS_ERR_SM2_BAD_INPUT_DATA + ret);
        }
        end2 = p + len;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        do {
            if ((ret = mbedtls_asn1_get_mpi(&p, end2, &r)))
            {
                ret += MBEDTLS_ERR_SM2_BAD_INPUT_DATA;
                break;
            }
            if ((ret = mbedtls_asn1_get_mpi(&p, end2, &s)))
            {
                ret += MBEDTLS_ERR_SM2_BAD_INPUT_DATA;
                break;
            }

            //r_len = mbedtls_mpi_size(&r);
            if ((ret = mbedtls_mpi_write_binary(&r, rs, 0x20)))
            {
                ret += MBEDTLS_ERR_SM2_BAD_INPUT_DATA;
                break;
            }

            //s_len = mbedtls_mpi_size(&s);
            if ((ret = mbedtls_mpi_write_binary(&s, rs + 0x20, 0x20)))
            {
                ret += MBEDTLS_ERR_SM2_BAD_INPUT_DATA;
                break;
            }
        } while (0);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
#endif
        sig = rs;
    }

#endif
    return mbedtls_sm2_verify( (mbedtls_sm2_context *) ctx, md_alg, hash, sig );
}

static int sm2_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;

    if( hash_len != mbedtls_md_get_size( mbedtls_md_info_from_type( md_alg ) )
            || sig_len == NULL )
        return( MBEDTLS_ERR_SM2_BAD_INPUT_DATA );
#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
    unsigned char z_buf[32], e_buf[32];
    if ((ret = mbedtls_sm2_hash_z((mbedtls_sm2_context*)ctx, md_alg, NULL, 0, z_buf)) != 0)
        return(ret);
    mbedtls_sm2_hash_e(md_alg, z_buf, hash, hash_len, e_buf);
#if defined(MBEDTLS_GM_PROTO_SSL1_1_LOG_ENABLE)
    print_hex(__FUNCTION__ " :mddata", hash, hash_len);
#endif
    hash = e_buf;
#endif
    ret = mbedtls_sm2_sign( (mbedtls_sm2_context *) ctx, md_alg, hash, sig,
            f_rng, p_rng );
    if( ret == 0 )
        *sig_len = ( ((mbedtls_sm2_context *) ctx)->grp.nbits + 7 ) / 8 * 2;
#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
    if ((ret == 0) && (*sig_len == 64)){
#if 0
        unsigned char rs[64];
        int offset = 0, zoff;
        memcpy(rs, sig, 64);
        sig[offset++] = 0x30;
        sig[offset++] = 0x00;
        for (zoff = 0; (zoff < 0x20) && (rs[zoff] == 0); zoff++);
        sig[offset++] = 0x02;
        sig[offset++] = 0x20 - zoff;
        if (rs[zoff] & 0x80) {
            sig[offset - 1] ++;
            sig[offset++] = 0x00;
        }
        memcpy(sig + offset, rs + zoff, 0x20 - zoff);
        offset += (0x20 - zoff);

        for (zoff = 0; (zoff < 0x20) && (rs[0x20+zoff] == 0); zoff++);
        sig[offset++] = 0x02;
        sig[offset++] = 0x20 - zoff;
        if (rs[0x20 + zoff] & 0x80) {
            sig[offset - 1] ++;
            sig[offset++] = 0x00;
        }
        memcpy(sig + offset, rs + 0x20 + zoff, 0x20 - zoff);
        offset += (0x20 - zoff);
        sig[1] = (unsigned char)(offset - 2);
        *sig_len = offset;
#else
        mbedtls_mpi r, s;
        int ret,ret2;
        unsigned char buf[16+64];
        unsigned char* p = buf + sizeof(buf);
        size_t len = 0;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_read_binary(&r, sig, 0x20);
        mbedtls_mpi_read_binary(&s, sig + 0x20, 0x20);
        ret  = mbedtls_asn1_write_mpi(&p, buf, &s);
        ret2 = mbedtls_asn1_write_mpi(&p, buf, &r);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        MBEDTLS_ASN1_CHK_ADD(len, ret);
        MBEDTLS_ASN1_CHK_ADD(len, ret2);

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        memcpy(sig, p, len);
        *sig_len = len;
#endif
    }
#endif
    return( ret );
}

static int sm2_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_md_type_t md_type = MBEDTLS_SM2_SPECIFIC_MD_ALGORITHM;
    size_t addlen = 1 +
        ( ((mbedtls_sm2_context *) ctx)->grp.nbits + 7 ) / 8 * 2 +
        mbedtls_md_get_size( mbedtls_md_info_from_type( md_type ) );
    ((void) f_rng);
    ((void) p_rng);

    if( ilen < addlen || osize < (ilen - addlen) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
    // TODO: DER -> C1C2C3
#endif
    return mbedtls_sm2_decrypt( (mbedtls_sm2_context *) ctx, md_type,
            input, ilen, output, olen );
}

static int sm2_encrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_md_type_t md_type = MBEDTLS_SM2_SPECIFIC_MD_ALGORITHM;
    size_t addlen = 1 +
        ( ((mbedtls_sm2_context *) ctx)->grp.nbits + 7 ) / 8 * 2 +
        mbedtls_md_get_size( mbedtls_md_info_from_type( md_type ) );

    if( osize < (ilen + addlen) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    int rv = mbedtls_sm2_encrypt( (mbedtls_sm2_context *) ctx, md_type,
            input, ilen, output, olen, f_rng, p_rng );
#ifdef MBEDTLS_GM_PROTO_SSL1_1_PATCH
    if (rv == 0)
    {   // C1C2C3 --> DER
        unsigned char output_tmp[0x100];
        size_t olen_tmp = *olen;
#if 0
        size_t offset = 0, zoff;
        memcpy(output_tmp, output, olen_tmp);

        output[offset++] = 0x30;
        output[offset++] = 0x81;
        output[offset++] = 0x00;
        for (zoff = 0; (zoff < 0x20) && (output_tmp[0x01 + zoff] == 0); zoff++);
        output[offset++] = 0x02;
        output[offset++] = (unsigned char)(0x20 - zoff);
        if (output_tmp[0x01 + zoff] & 0x80) {
            output[offset - 1] ++;
            output[offset++] = 0x00;
        }
        memcpy(output + offset, output_tmp + 0x01 + zoff, 0x20 - zoff);
        offset += (0x20 - zoff);

        for (zoff = 0; (zoff < 0x20) && (output_tmp[0x01 + zoff] == 0); zoff++);
        output[offset++] = 0x02;
        output[offset++] = (unsigned char)(0x20 - zoff);
        if (output_tmp[0x21 + zoff] & 0x80) {
            output[offset - 1] ++;
            output[offset++] = 0x00;
        }
        memcpy(output + offset, output_tmp + 0x21 + zoff, 0x20 - zoff);
        offset += (0x20 - zoff);

        output[offset++] = 0x04;
        output[offset++] = 0x20;
        memcpy(output + offset, output_tmp + olen_tmp - 0x20, 0x20);
        offset += 0x20;

        output[offset++] = 0x04;
        output[offset++] = (unsigned char)(olen_tmp - 0x61);
        memcpy(output + offset, output_tmp + 0x41, olen_tmp - 0x61);
        offset += (olen_tmp - 0x61);
        output[2] = (unsigned char)(offset - 3);

        *olen = offset;
#else
        mbedtls_mpi x, y;
        int ret, ret2;
        unsigned char* p = output_tmp + sizeof(output_tmp);
        size_t len = 0;

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, output_tmp, output + 0x41, olen_tmp - 0x61));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, output_tmp, output + olen_tmp - 0x20, 0x20));

        mbedtls_mpi_init(&x);
        mbedtls_mpi_init(&y);
        mbedtls_mpi_read_binary(&x, output + 0x01, 0x20);
        mbedtls_mpi_read_binary(&y, output + 0x21, 0x20);
        ret  = mbedtls_asn1_write_mpi(&p, output_tmp, &y);
        ret2 = mbedtls_asn1_write_mpi(&p, output_tmp, &x);
        mbedtls_mpi_free(&x);
        mbedtls_mpi_free(&y);
        MBEDTLS_ASN1_CHK_ADD(len, ret);
        MBEDTLS_ASN1_CHK_ADD(len, ret2);

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, output_tmp, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, output_tmp,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        memcpy(output, p, len);
        *olen = len;
#endif
    }
#if defined(MBEDTLS_GM_PROTO_SSL1_1_LOG_ENABLE)
    unsigned char P_buf[0x41];
    size_t P_size = 0;
    mbedtls_ecp_point_write_binary(&((mbedtls_sm2_context*)ctx)->grp, &((mbedtls_sm2_context*)ctx)->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &P_size, P_buf, 0x41);
    print_hex(__FUNCTION__ " :P", P_buf, P_size);
    print_hex(__FUNCTION__ " :input/pms", input, ilen);
    print_hex(__FUNCTION__ " :output/encbytes1", output, *olen);
#endif
#endif
    return rv;
}

static void *sm2_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sm2_context ) );

    if( ctx != NULL )
        mbedtls_sm2_init( (mbedtls_sm2_context *) ctx );

    return( ctx );
}

static void sm2_free_wrap( void *ctx )
{
    mbedtls_sm2_free( (mbedtls_sm2_context *) ctx );
    mbedtls_free( ctx );
}

const mbedtls_pk_info_t mbedtls_sm2_info = {
    MBEDTLS_PK_SM2,
    "SM2",
    eckey_get_bitlen,   /* Compatible key structures */
    sm2_can_do,
    sm2_verify_wrap,
    sm2_sign_wrap,
    sm2_decrypt_wrap,
    sm2_encrypt_wrap,
    eckey_check_pair,   /* Compatible key structures */
    sm2_alloc_wrap,
    sm2_free_wrap,
    eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_SM2_C */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA );
}

static size_t rsa_alt_get_bitlen( const void *ctx )
{
    const mbedtls_rsa_alt_context *rsa_alt = (const mbedtls_rsa_alt_context *) ctx;

    return( 8 * rsa_alt->key_len_func( rsa_alt->key ) );
}

static int rsa_alt_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_alt_context *rsa_alt = (mbedtls_rsa_alt_context *) ctx;

#if SIZE_MAX > UINT_MAX
    if( UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = rsa_alt->key_len_func( rsa_alt->key );

    return( rsa_alt->sign_func( rsa_alt->key, f_rng, p_rng, MBEDTLS_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_alt_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_alt_context *rsa_alt = (mbedtls_rsa_alt_context *) ctx;

    ((void) f_rng);
    ((void) p_rng);

    if( ilen != rsa_alt->key_len_func( rsa_alt->key ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( rsa_alt->decrypt_func( rsa_alt->key,
                MBEDTLS_RSA_PRIVATE, olen, input, output, osize ) );
}

#if defined(MBEDTLS_RSA_C)
static int rsa_alt_check_pair( const void *pub, const void *prv )
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret;

    if( rsa_alt_get_bitlen( prv ) != rsa_get_bitlen( pub ) )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    memset( hash, 0x2a, sizeof( hash ) );

    if( ( ret = rsa_alt_sign_wrap( (void *) prv, MBEDTLS_MD_NONE,
                                   hash, sizeof( hash ),
                                   sig, &sig_len, NULL, NULL ) ) != 0 )
    {
        return( ret );
    }

    if( rsa_verify_wrap( (void *) pub, MBEDTLS_MD_NONE,
                         hash, sizeof( hash ), sig, sig_len ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

static void *rsa_alt_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_alt_context ) );

    if( ctx != NULL )
        memset( ctx, 0, sizeof( mbedtls_rsa_alt_context ) );

    return( ctx );
}

static void rsa_alt_free_wrap( void *ctx )
{
    mbedtls_zeroize( ctx, sizeof( mbedtls_rsa_alt_context ) );
    mbedtls_free( ctx );
}

const mbedtls_pk_info_t mbedtls_rsa_alt_info = {
    MBEDTLS_PK_RSA_ALT,
    "RSA-alt",
    rsa_alt_get_bitlen,
    rsa_alt_can_do,
    NULL,
    rsa_alt_sign_wrap,
    rsa_alt_decrypt_wrap,
    NULL,
#if defined(MBEDTLS_RSA_C)
    rsa_alt_check_pair,
#else
    NULL,
#endif
    rsa_alt_alloc_wrap,
    rsa_alt_free_wrap,
    NULL,
};

#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#endif /* MBEDTLS_PK_C */
