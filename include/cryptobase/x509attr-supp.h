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

#include "cryptobase/x509ac.h"
#include "cryptobase/x509attr.h"

#include <openssl/err.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* function for SvceAuthInfo attribute used for Service Authentication
 * Information and Access Identity */
int X509attr_SvceAuthInfo_add_value( X509_ATTRIBUTE *attr, SvceAuthInfo *val );
/* function for IetfAttrSyntax attribute used for Charging Identity and
 * Group */
int X509attr_IetfAttrSyntax_add_value( X509_ATTRIBUTE *attr, IetfAttrSyntax *val );
/* function for RoleSyntax attribute used for Role */
int X509attr_RoleSyntax_add_value( X509_ATTRIBUTE *attr, RoleSyntax *val );
/* function for Clearance attribute used for Clearance  */
int X509attr_Clearance_add_value( X509_ATTRIBUTE *attr, Clearance *val);
/* general attribute value addition */
int X509attr_attribute_add_value( X509_ATTRIBUTE *attr, int attrtype , char *p, int len);

#ifdef __cplusplus
}
#endif
