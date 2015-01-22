/*
 * x509attr.h
 *
 *  Created on: Feb 27, 2013
 *      Author: Felipe Menegola Blauth
 *  giovani.milanez@gmail.com
 */

#ifndef _attr_h_
#define _attr_h_

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C"
{
#endif

// lil hack here
#define DECLARE_ASN1_DUP_FUNCTION(stname) 				\
	stname * stname##_dup(stname *x);

typedef struct SvceAuthInfo_st
{
	GENERAL_NAME *service;
	GENERAL_NAME *ident;
	ASN1_OCTET_STRING *authInfo;
} SvceAuthInfo;

typedef struct IetfAttrSyntax_st
{
	GENERAL_NAMES *policyAuthority;
	int type;
	union
	{
		ASN1_OCTET_STRING *octets;
		ASN1_OBJECT *oid;
		ASN1_UTF8STRING *string;
	} values;
} IetfAttrSyntax;

typedef struct RoleSyntax_st
{
	GENERAL_NAMES *roleAuthority;
	GENERAL_NAME  *roleName;
} RoleSyntax;

DECLARE_ASN1_ITEM(SvceAuthInfo)
DECLARE_ASN1_FUNCTIONS(SvceAuthInfo)
DECLARE_ASN1_DUP_FUNCTION(SvceAuthInfo)

DECLARE_ASN1_ITEM(IetfAttrSyntax)
DECLARE_ASN1_FUNCTIONS(IetfAttrSyntax)
DECLARE_ASN1_DUP_FUNCTION(IetfAttrSyntax)

DECLARE_ASN1_ITEM(RoleSyntax)
DECLARE_ASN1_FUNCTIONS(RoleSyntax)
DECLARE_ASN1_DUP_FUNCTION(RoleSyntax)

typedef struct SecurityCategory_st
{
	ASN1_OBJECT    *type;
	ASN1_TYPE     *value;
} SecurityCategory;

typedef struct Clearance_st
{
	ASN1_OBJECT *policyId;
	ASN1_BIT_STRING *ClassList;
	SecurityCategory *securityCategories;
}Clearance;

DECLARE_ASN1_ITEM(Clearance)
DECLARE_ASN1_FUNCTIONS(Clearance)
DECLARE_ASN1_DUP_FUNCTION(Clearance)

DECLARE_ASN1_ITEM(SecurityCategory)
DECLARE_ASN1_FUNCTIONS(SecurityCategory)
DECLARE_ASN1_DUP_FUNCTION(SecurityCategory)

#ifdef __cplusplus
}
#endif

#endif
