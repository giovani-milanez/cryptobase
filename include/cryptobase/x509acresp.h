#ifndef _x509acreq_h_
#define _x509acreq_h_

#include "cryptobase/x509ac.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PEM_STRING_ATTRIBUTE_CERTIFICATE_RESPONSE "ATTRIBUTE CERTIFICATE RESPONSE"

/**
 * ACStatus ::= INTEGER {
    granted                (0),
    -- when the ACStatus contains the value zero an AttributeCertificate, as
       requested, is present.
    rejection              (1)
     }

    ACFailureInfo ::= INTEGER {
    badAlg               (0),
      -- unrecognized or unsupported Algorithm Identifier
    badRequest           (2),
      -- transaction not permitted or supported
    badDataFormat        (5),
      -- the data submitted has the wrong format
    integrityFail	 (14),
      -- the signature integrity is compromised
    notApproved		(15),
      -- the AA declined to grant the holder's attributes
    unacceptedExtension (16),
      -- the requested extension is not supported by the AA.
    untrustedRequester  (17),
      -- the requester is not trusted by the AA.
    untrustedHolder	(18),
      -- the holder is not trusted by the AA.
    unsupportedAttribute (19),
      -- one of the attributes requested is not supported by the AA.
    systemFailure       (25)
      -- the request cannot be handled due to system failure  }
 */
typedef struct CRYPTOBASE_API X509AC_STATUS_INFO_st
{
	ASN1_INTEGER *status;
	ASN1_UTF8STRING *text;
	ASN1_INTEGER *failInfo;
} X509AC_STATUS_INFO;


typedef struct CRYPTOBASE_API X509AC_RESP_st
{
	X509AC_STATUS_INFO *statusInfo;
	STACK_OF(X509AC) *attrCert;
} X509AC_RESP;


DECLARE_ASN1_ITEM(X509AC_STATUS_INFO)
DECLARE_ASN1_FUNCTIONS(X509AC_STATUS_INFO)
DECLARE_ASN1_DUP_FUNCTION(X509AC_STATUS_INFO)

DECLARE_ASN1_ITEM(X509AC_RESP)
DECLARE_ASN1_FUNCTIONS(X509AC_RESP)
DECLARE_ASN1_DUP_FUNCTION(X509AC_RESP)
DECLARE_PEM_rw(X509AC_RESP, X509AC_RESP)


#ifdef __cplusplus
}
#endif

#endif // _x509acreq_h_
