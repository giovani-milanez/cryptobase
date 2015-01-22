/*****************************************************************
*
* This code has been developed at:
*************************************
* Pervasive Computing Laboratory
*************************************
* Telematic Engineering Dept.
* Carlos III university
* Contact:
*		Daniel D�az Sanchez
*		Florina Almenarez
*		Andr�s Mar�n
*************************************
* Mail:	dds[@_@]it.uc3m.es
* Web: http://www.it.uc3m.es/dds
* Blog: http://rubinstein.gast.it.uc3m.es/research/dds
* Team: http://www.it.uc3m.es/pervasive
**********************************************************
* This code is released under the terms of OpenSSL license
* http://www.openssl.org
*****************************************************************/

#include "cryptobase/x509attr.h"

/*


   Some of the attribute types defined below make use of the
   IetfAttrSyntax type, also defined below.  The reasons for using this
   type are:

   1. It allows a separation between the AC issuer and the attribute
      policy authority.  This is useful for situations where a single
      policy authority (e.g. an organization) allocates attribute
      values, but where multiple AC issuers are deployed for performance
      or other reasons.

   2. The syntaxes allowed for values are restricted to OCTET STRING,
      OBJECT IDENTIFIER, and UTF8String, which significantly reduces the
      complexity associated with matching more general syntaxes.  All
      multi-valued attributes using this syntax are restricted so that
      each value MUST use the same choice of value syntax.  For example,
      AC issuers must not use one value with an oid and a second value
      with a string.

               IetfAttrSyntax ::= SEQUENCE {
                    policyAuthority [0] GeneralNames    OPTIONAL,
                    values          SEQUENCE OF CHOICE {
                                  octets    OCTET STRING,
                                  oid       OBJECT IDENTIFIER,
                                  string    UTF8String
                   }
               }

   In the descriptions below, each attribute type is either tagged
   "Multiple Allowed" or "One Attribute value only; multiple values
   within the IetfAttrSyntax".  This refers to the SET OF
   AttributeValues; the AttributeType still only occurs once, as
   specified in section 4.2.7.


*/
/* *******************************
   RFC 3281 ATTRIBUTES
   ******************************* */
/*
   SERVICE AUTHENTICATION INFORMATION
   __________________________________

   The SvceAuthInfo attribute identifies the AC holder to the
   server/service by a name, and the attribute MAY include optional
   service specific authentication information.  Typically this will
   contain a username/password pair for a "legacy" application.

   This attribute provides information that can be presented by the AC
   verifier to be interpreted and authenticated by a separate
   application within the target system.  Note that this is a different
   use to that intended for the accessIdentity attribute in 4.4.2 below.

   This attribute type will typically be encrypted when the authInfo
   field contains sensitive information, such as a password.

      name      id-aca-authenticationInfo
      OID       { id-aca 1 }
      Syntax    SvceAuthInfo
      values:   Multiple allowed

           SvceAuthInfo ::=    SEQUENCE {
                service   GeneralName,
                ident     GeneralName,
                authInfo  OCTET STRING OPTIONAL
           }
*/

/*
   ACCESS IDENTITY
   _______________

   The accessIdentity attribute identifies the AC holder to the
   server/service.  For this attribute the authInfo field MUST NOT be
   present.

   This attribute is intended to be used to provide information about
   the AC holder, that can be used by the AC verifier (or a larger
   system of which the AC verifier is a component) to authorize the
   actions of the AC holder within the AC verifier's system.  Note that
   this is a different use to that intended for the svceAuthInfo
   attribute described in 4.4.1 above.

      name      id-aca-accessIdentity
      OID       { id-aca 2 }
      syntax    SvceAuthInfo
      values:   Multiple allowed

*/

ASN1_SEQUENCE(SvceAuthInfo) = {
	ASN1_SIMPLE(SvceAuthInfo, service, GENERAL_NAME),
	ASN1_SIMPLE(SvceAuthInfo, ident, GENERAL_NAME),
	ASN1_OPT(SvceAuthInfo, authInfo, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(SvceAuthInfo)

IMPLEMENT_ASN1_FUNCTIONS(SvceAuthInfo)
IMPLEMENT_ASN1_DUP_FUNCTION(SvceAuthInfo)
/*
   Charging Identity
   _________________
   The chargingIdentity attribute identifies the AC holder for charging
   purposes.  In general, the charging identity will be different from
   other identities of the holder.  For example, the holder's company
   may be charged for service.

      name      id-aca-chargingIdentity
      OID       { id-aca 3 }
      syntax    IetfAttrSyntax
      values:   One Attribute value only; multiple values within the
                IetfAttrSyntax

Group

   The group attribute carries information about group memberships of
   the AC holder.

      name      id-aca-group
      OID       { id-aca 4 }
      syntax    IetfAttrSyntax
      values:   One Attribute value only; multiple values within the
                IetfAttrSyntax

*/

ASN1_CHOICE(IetfAttrValues)= {
	ASN1_SIMPLE(IetfAttrSyntax ,values.octets , ASN1_OCTET_STRING ),
	ASN1_SIMPLE(IetfAttrSyntax ,values.oid , ASN1_OBJECT ),
	ASN1_SIMPLE(IetfAttrSyntax ,values.string , ASN1_UTF8STRING )
}ASN1_CHOICE_END_selector(IetfAttrSyntax, IetfAttrValues, type);

ASN1_SEQUENCE(IetfAttrSyntax) = {
	//ASN1_OPT(IetfAttrSyntax, policyAuthority, GENERAL_NAMES, 0),
	ASN1_SEQUENCE_OF_OPT(IetfAttrSyntax,policyAuthority,GENERAL_NAME),
	ASN1_EX_COMBINE(0, 0, IetfAttrValues)
}ASN1_SEQUENCE_END(IetfAttrSyntax);

IMPLEMENT_ASN1_FUNCTIONS(IetfAttrSyntax)
IMPLEMENT_ASN1_DUP_FUNCTION(IetfAttrSyntax)

/*
  Role

   The role attribute, specified in [X.509-2000], carries information
   about role allocations of the AC holder.

   The syntax used for this attribute is:

         RoleSyntax ::= SEQUENCE {
                 roleAuthority   [0] GeneralNames OPTIONAL,
                 roleName        [1] GeneralName
         }

   The roleAuthority field MAY be used to specify the issuing authority
   for the role specification certificate.  There is no requirement that
   a role specification certificate necessarily exists for the
   roleAuthority.  This differs from [X.500-2000], where the
   roleAuthority field is assumed to name the issuer of a role
   specification certificate.  For example, to distinguish the
   administrator role as defined by "Baltimore" from that defined by
   "SPYRUS", one could put the value "urn:administrator" in the roleName
   field and the value "Baltimore" or "SPYRUS" in the roleAuthority
   field.

   The roleName field MUST be present, and roleName MUST use the
   uniformResourceIdentifier CHOICE of the GeneralName.

      name      id-at-role
      OID       { id-at 72 }
      syntax    RoleSyntax
      values:   Multiple allowed

*/

ASN1_SEQUENCE(RoleSyntax) = {
	ASN1_SEQUENCE_OF_OPT(RoleSyntax, roleAuthority, GENERAL_NAME),
	ASN1_SIMPLE(RoleSyntax, roleName, GENERAL_NAME)
} ASN1_SEQUENCE_END(RoleSyntax);

IMPLEMENT_ASN1_FUNCTIONS(RoleSyntax)
IMPLEMENT_ASN1_DUP_FUNCTION(RoleSyntax)
/*
   Clearance

   The clearance attribute, specified in [X.501-1993], carries clearance
   (associated with security labeling) information about the AC holder.

   The policyId field is used to identify the security policy to which
   the clearance relates.  The policyId indicates the semantics of the
   classList and securityCategories fields.

   This specification includes the classList field exactly as it is
   specified in [X.501-1993].  Additional security classification
   values, and their position in the classification hierarchy, may be
   defined by a security policy as a local matter or by bilateral
   agreement.  The basic security classification hierarchy is, in
   ascending order: unmarked, unclassified, restricted, confidential,
   secret, and top-secret.

   An organization can develop its own security policy that defines
   security classification values and their meanings.  However, the BIT
   STRING positions 0 through 5 are reserved for the basic security
   classification hierarchy.

   If present, the SecurityCategory field provides further authorization
   information.  The security policy identified by the policyId field
   indicates the syntaxes that are allowed to be present in the
   securityCategories SET.  An OBJECT IDENTIFIER identifies each of the
   allowed syntaxes.  When one of these syntaxes is present in the
   securityCategories SET, the OBJECT IDENTIFIER associated with that
   syntax is carried in the SecurityCategory.type field.

            Clearance  ::=  SEQUENCE {
                 policyId  [0] OBJECT IDENTIFIER,
                 classList [1] ClassList DEFAULT {unclassified},
                 securityCategories
                           [2] SET OF SecurityCategory OPTIONAL
            }

            ClassList  ::=  BIT STRING {
                 unmarked       (0),
                 unclassified   (1),
                 restricted     (2)
                 confidential   (3),
                 secret         (4),
                 topSecret      (5)
            }

            SecurityCategory ::= SEQUENCE {
                 type      [0]  IMPLICIT OBJECT IDENTIFIER,
                 value     [1]  ANY DEFINED BY type
            }

            -- This is the same as the original syntax which was defined
            -- using the MACRO construct, as follows:
            -- SecurityCategory ::= SEQUENCE {
            --      type      [0]  IMPLICIT SECURITY-CATEGORY,
            --      value     [1]  ANY DEFINED BY type
            -- }
            --
            -- SECURITY-CATEGORY MACRO  ::=
            -- BEGIN
            -- TYPE NOTATION ::= type | empty
            -- VALUE NOTATION ::= value (VALUE OBJECT IDENTIFIER)
            -- END

       name      { id-at-clearance }
       OID       { joint-iso-ccitt(2) ds(5) module(1)
                   selected-attribute-types(5) clearance (55) }
       syntax    Clearance - imported from [X.501-1993]
       values    Multiple allowed
*/

/*
ASN1_SEQUENCE(SecurityCategory)={
	ASN1_IMP(SecurityCategory,type,ASN1_OBJECT,0),
	ASN1_SIMPLE(SecurityCategory,value,ASN1_TYPE)
}ASN1_SEQUENCE_END(SecurityCategory);

IMPLEMENT_ASN1_FUNCTIONS(SecurityCategory)
IMPLEMENT_ASN1_DUP_FUNCTION(SecurityCategory)
*/

#ifdef __cplusplus
}
#endif



