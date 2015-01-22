/*
 * x509ac.c
 *
 *  Created on: Feb 27, 2013
 *      Author: Felipe Menegola Blauth
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/x509ac.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(X509AC_OBJECT_DIGESTINFO) =
{
	ASN1_SIMPLE(X509AC_OBJECT_DIGESTINFO, type, ASN1_ENUMERATED),
	ASN1_OPT(X509AC_OBJECT_DIGESTINFO, othertype, ASN1_OBJECT),
	ASN1_SIMPLE(X509AC_OBJECT_DIGESTINFO, algor, X509_ALGOR),
	ASN1_SIMPLE(X509AC_OBJECT_DIGESTINFO, digest, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X509AC_OBJECT_DIGESTINFO)

ASN1_SEQUENCE(X509AC_ISSUER_SERIAL) =
{
	ASN1_SEQUENCE_OF(X509AC_ISSUER_SERIAL, issuer, GENERAL_NAME),
	ASN1_SIMPLE(X509AC_ISSUER_SERIAL, serial, ASN1_INTEGER),
	ASN1_OPT(X509AC_ISSUER_SERIAL, issuerUniqueID, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X509AC_ISSUER_SERIAL)

ASN1_SEQUENCE(X509AC_V2FORM) =
{
	ASN1_SEQUENCE_OF_OPT(X509AC_V2FORM, issuer, GENERAL_NAME),
	ASN1_IMP_OPT(X509AC_V2FORM, baseCertID, X509AC_ISSUER_SERIAL, 0),
	ASN1_IMP_OPT(X509AC_V2FORM, digest, X509AC_OBJECT_DIGESTINFO, 1)
} ASN1_SEQUENCE_END(X509AC_V2FORM)

ASN1_CHOICE(X509AC_ISSUER) =
{
	ASN1_SEQUENCE_OF(X509AC_ISSUER, d.v1Form, GENERAL_NAME),
	ASN1_IMP(X509AC_ISSUER, d.v2Form, X509AC_V2FORM, 0)
} ASN1_CHOICE_END(X509AC_ISSUER)

ASN1_SEQUENCE(X509AC_HOLDER) =
{
	//	ASN1_IMP_OPT(X509AC_HOLDER, baseCertID, X509AC_ISSUER_SERIAL, 0),
	ASN1_IMP_OPT(X509AC_HOLDER, baseCertID, X509AC_ISSUER_SERIAL, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(X509AC_HOLDER, entity, GENERAL_NAME, 1),
	ASN1_IMP_OPT(X509AC_HOLDER, objectDigestInfo, X509AC_OBJECT_DIGESTINFO, 2)
} ASN1_SEQUENCE_END(X509AC_HOLDER)

ASN1_SEQUENCE(X509AC_VAL) =
{
	ASN1_SIMPLE(X509AC_VAL, notBefore, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(X509AC_VAL, notAfter, ASN1_GENERALIZEDTIME)
} ASN1_SEQUENCE_END(X509AC_VAL)

ASN1_SEQUENCE(X509AC_INFO) =
{
	//	ASN1_OPT(X509AC_INFO, version, ASN1_INTEGER),
	ASN1_SIMPLE(X509AC_INFO, version, ASN1_INTEGER),
	ASN1_SIMPLE(X509AC_INFO, holder, X509AC_HOLDER),
	ASN1_SIMPLE(X509AC_INFO, issuer, X509AC_ISSUER),
	ASN1_SIMPLE(X509AC_INFO, algor, X509_ALGOR),
	ASN1_SIMPLE(X509AC_INFO, serial, ASN1_INTEGER),
	ASN1_SIMPLE(X509AC_INFO, validity, X509AC_VAL),
	//	ASN1_SEQUENCE_OF_OPT(X509AC_INFO, attributes, X509_ATTRIBUTE),
	ASN1_SEQUENCE_OF(X509AC_INFO, attributes, X509_ATTRIBUTE),
	ASN1_OPT(X509AC_INFO, issuerUniqueID, ASN1_BIT_STRING),
	ASN1_SEQUENCE_OF_OPT(X509AC_INFO, extensions, X509_EXTENSION)
} ASN1_SEQUENCE_END(X509AC_INFO)

ASN1_SEQUENCE(X509AC) =
{
	ASN1_SIMPLE(X509AC, info, X509AC_INFO),
	ASN1_SIMPLE(X509AC, algor, X509_ALGOR),
	ASN1_SIMPLE(X509AC, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X509AC)

IMPLEMENT_ASN1_FUNCTIONS(X509AC_OBJECT_DIGESTINFO)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_V2FORM)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_HOLDER)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_ISSUER)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_INFO)
IMPLEMENT_ASN1_FUNCTIONS(X509AC)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_VAL)


IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_OBJECT_DIGESTINFO)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_ISSUER_SERIAL)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_V2FORM)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_HOLDER)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_ISSUER)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_VAL)

IMPLEMENT_PEM_rw(X509AC, X509AC, PEM_STRING_ATTRIBUTE_CERTIFICATE, X509AC)
IMPLEMENT_STACK_OF(X509AC)
IMPLEMENT_ASN1_SET_OF(X509AC)
