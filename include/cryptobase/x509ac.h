/*
 * x509ac.h
 *
 *  Created on: Feb 27, 2013
 *      Author: Felipe Menegola Blauth
 *  giovani.milanez@gmail.com
 */

#ifndef _x509ac_h_
#define _x509ac_h_

#include "cryptobase/Defs.h"

#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define PEM_STRING_ATTRIBUTE_CERTIFICATE "ATTRIBUTE CERTIFICATE"

// lil hack here
#define DECLARE_ASN1_DUP_FUNCTION(stname) 				\
	CRYPTOBASE_API stname * stname##_dup(stname *x);

typedef struct CRYPTOBASE_API X509AC_OBJECT_DIGESTINFO_st
{
	ASN1_ENUMERATED *type;
	ASN1_OBJECT *othertype;
	X509_ALGOR *algor;
	ASN1_BIT_STRING *digest;
} X509AC_OBJECT_DIGESTINFO;

typedef struct CRYPTOBASE_API X509AC_ISSUER_SERIAL_st
{
	GENERAL_NAMES *issuer;
	ASN1_INTEGER *serial;
	ASN1_BIT_STRING *issuerUniqueID;
} X509AC_ISSUER_SERIAL;

typedef struct CRYPTOBASE_API X509AC_V2FORM_st
{
	GENERAL_NAMES *issuer;
	X509AC_ISSUER_SERIAL *baseCertID;
	X509AC_OBJECT_DIGESTINFO *digest;
} X509AC_V2FORM;

typedef struct CRYPTOBASE_API X509AC_ISSUER_st
{
	int type;
	union
	{
		GENERAL_NAMES *v1Form;
		X509AC_V2FORM *v2Form;
	} d;
} X509AC_ISSUER;


typedef struct CRYPTOBASE_API X509AC_HOLDER_st
{
	X509AC_ISSUER_SERIAL *baseCertID;
	GENERAL_NAMES *entity;
	X509AC_OBJECT_DIGESTINFO *objectDigestInfo;
} X509AC_HOLDER;

typedef struct CRYPTOBASE_API X509AC_VAL_st {
	ASN1_GENERALIZEDTIME *notBefore;
	ASN1_GENERALIZEDTIME *notAfter;
} X509AC_VAL;

typedef struct CRYPTOBASE_API X509AC_INFO_st
{
	ASN1_INTEGER *version;
	X509AC_HOLDER *holder;
	X509AC_ISSUER *issuer;
	X509_ALGOR *algor;
	ASN1_INTEGER *serial;
	X509AC_VAL *validity;
	STACK_OF(X509_ATTRIBUTE) *attributes;
	//X509_ATTRIBUTE *attributes;
	ASN1_BIT_STRING *issuerUniqueID;
	STACK_OF(X509_EXTENSION) *extensions;
} X509AC_INFO;

typedef struct CRYPTOBASE_API X509AC_st
{
	X509AC_INFO *info;
	X509_ALGOR *algor;
	ASN1_BIT_STRING *signature;
} X509AC;

DECLARE_ASN1_ITEM(X509AC)
DECLARE_ASN1_FUNCTIONS(X509AC)
DECLARE_ASN1_DUP_FUNCTION(X509AC)
DECLARE_PEM_rw(X509AC, X509AC)
DECLARE_STACK_OF(X509AC)
DECLARE_ASN1_SET_OF(X509AC)

DECLARE_ASN1_ITEM(X509AC_INFO)
DECLARE_ASN1_FUNCTIONS(X509AC_INFO)
DECLARE_ASN1_DUP_FUNCTION(X509AC_INFO)

DECLARE_ASN1_ITEM(X509AC_ISSUER_SERIAL)
DECLARE_ASN1_FUNCTIONS(X509AC_ISSUER_SERIAL)
DECLARE_ASN1_DUP_FUNCTION(X509AC_ISSUER_SERIAL)

DECLARE_ASN1_ITEM(X509AC_ISSUER)
DECLARE_ASN1_FUNCTIONS(X509AC_ISSUER)
DECLARE_ASN1_DUP_FUNCTION(X509AC_ISSUER)

DECLARE_ASN1_ITEM(X509AC_HOLDER)
DECLARE_ASN1_FUNCTIONS(X509AC_HOLDER)
DECLARE_ASN1_DUP_FUNCTION(X509AC_HOLDER)

DECLARE_ASN1_ITEM(X509AC_V2FORM)
DECLARE_ASN1_FUNCTIONS(X509AC_V2FORM)
DECLARE_ASN1_DUP_FUNCTION(X509AC_V2FORM)

DECLARE_ASN1_ITEM(X509AC_OBJECT_DIGESTINFO)
DECLARE_ASN1_FUNCTIONS(X509AC_OBJECT_DIGESTINFO)
DECLARE_ASN1_DUP_FUNCTION(X509AC_OBJECT_DIGESTINFO)

DECLARE_ASN1_ITEM(X509AC_VAL)
DECLARE_ASN1_FUNCTIONS(X509AC_VAL)
DECLARE_ASN1_DUP_FUNCTION(X509AC_VAL)

#define sk_X509AC_new(cmp)                 SKM_sk_new(X509AC, (cmp))
#define sk_X509AC_new_null()               SKM_sk_new_null(X509AC)
#define sk_X509AC_free(st)                 SKM_sk_free(X509AC, (st))
#define sk_X509AC_pop_free(st, free_func)  SKM_sk_pop_free(X509AC, (st), (free_func))
#define sk_X509AC_dup(st)                  SKM_sk_dup(X509AC, st)

/* get & set */
#define sk_X509AC_num(st)                  SKM_sk_num(X509AC, (st))
#define sk_X509AC_value(st, i)             SKM_sk_value(X509AC, (st), (i))
#define sk_X509AC_set(st, i, val)          SKM_sk_set(X509AC, (st), (i), (val))

/* add value */
#define sk_X509AC_insert(st, val, i)       SKM_sk_insert(X509AC, (st), (val), (i))
#define sk_X509AC_push(st, val)            SKM_sk_push(X509AC, (st), (val))
#define sk_X509AC_unshift(st, val)         SKM_sk_unshift(X509AC, (st), (val))

/* sort & find */
#define sk_X509AC_set_cmp_func(st, cmp)    SKM_sk_set_cmp_func(X509AC, (st), (cmp))
#define sk_X509AC_sort(st)                 SKM_sk_sort(X509AC, (st))
#define sk_X509AC_is_sorted(st)            SKM_sk_is_sorted(X509AC, (st))
#define sk_X509AC_find(st, val)            SKM_sk_find(X509AC, (st), (val))
#define sk_X509AC_find_ex(st, val)         SKM_sk_find_ex(X509AC, (st), (val))

/* delete value */
#define sk_X509AC_delete(st, i)            SKM_sk_delete(X509AC, (st), (i))
#define sk_X509AC_delete_ptr(st, ptr)      SKM_sk_delete_ptr(X509AC, (st), (ptr))
#define sk_X509AC_pop(st)                  SKM_sk_pop(X509AC, (st))
#define sk_X509AC_shift(st)                SKM_sk_shift(X509AC, (st))
#define sk_X509AC_zero(st)                 SKM_sk_zero(X509AC, (st))

#ifdef __cplusplus
}
#endif

#endif // _x509ac_h_
