/*
 * x509acresp.c
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */


#include "cryptobase/x509acresp.h"

ASN1_SEQUENCE(X509AC_STATUS_INFO) =
{
	ASN1_SIMPLE(X509AC_STATUS_INFO, status, ASN1_INTEGER),
	ASN1_OPT(X509AC_STATUS_INFO, text, ASN1_UTF8STRING),
	ASN1_OPT(X509AC_STATUS_INFO, failInfo, ASN1_INTEGER)
} ASN1_SEQUENCE_END(X509AC_STATUS_INFO)

ASN1_SEQUENCE(X509AC_RESP) =
{
	ASN1_SIMPLE(X509AC_RESP, statusInfo, X509AC_STATUS_INFO),
	ASN1_SEQUENCE_OF_OPT(X509AC_RESP, attrCert, X509AC)
} ASN1_SEQUENCE_END(X509AC_RESP)

IMPLEMENT_ASN1_FUNCTIONS(X509AC_STATUS_INFO)
IMPLEMENT_ASN1_FUNCTIONS(X509AC_RESP)

IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_STATUS_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(X509AC_RESP)

IMPLEMENT_PEM_rw(X509AC_RESP, X509AC_RESP, PEM_STRING_ATTRIBUTE_CERTIFICATE_RESPONSE, X509AC_RESP)
