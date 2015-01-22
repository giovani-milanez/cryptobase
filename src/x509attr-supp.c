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

#include "cryptobase/x509attr-supp.h"

int X509attr_attribute_add_value( X509_ATTRIBUTE *attr, int attrtype , char *p, int len)
{
	ASN1_TYPE *ttmp;
	ASN1_STRING *stmp;
	int atype;
	if(attrtype & MBSTRING_FLAG)
	{
		stmp = ASN1_STRING_set_by_NID(NULL, (const unsigned char*)p,
			len, attrtype, NID_id_aca_authenticationInfo
			/*OBJ_obj2nid(x509_attr->object)*/);
			if(!stmp)
			{
				X509err(X509_F_X509_ATTRIBUTE_SET1_DATA, ERR_R_ASN1_LIB);
				goto err;
			}
			atype = stmp->type;
	}
	else
	{
		if(!(stmp = ASN1_STRING_type_new(attrtype)))
			goto err;
		if(!ASN1_STRING_set(stmp, p, len))
			goto err;
		atype = attrtype;
	}
	attr->single = 0;
	if( attr->value.set == NULL )
		if(!(attr->value.set = sk_ASN1_TYPE_new_null())) goto err;
	if(!(ttmp = ASN1_TYPE_new())) goto err;
	if(!sk_ASN1_TYPE_push(attr->value.set, ttmp)) goto err;

	ASN1_TYPE_set(ttmp, atype, stmp);
	return 1;
err:
	return 0;
}

int X509attr_SvceAuthInfo_add_value( X509_ATTRIBUTE *attr, SvceAuthInfo *val )
{
	// TODO implement
	return 0;
//	int	enc_length = 0, ret=0;
//	char* bufaux = NULL;
//	char* p = NULL;
//	char** pp = NULL;
//	int attrtype;
//	SvceAuthInfo *aux_val = NULL;
//
//	if( attr == NULL)
//		return(0);
//
//	enc_length = i2d_SvceAuthInfo(val, NULL);
//
//	if( (bufaux = (char*)OPENSSL_malloc(enc_length)) == NULL)
//		goto err;
//
//	p = bufaux;
//	pp = &p;
//
//	aux_val = (SvceAuthInfo*) SvceAuthInfo_dup(val);
//	i2d_SvceAuthInfo(val, (unsigned char**)pp);
//	attrtype = V_ASN1_SEQUENCE;
//	ret = X509attr_attribute_add_value(attr,attrtype,bufaux,enc_length);
//	if( bufaux != NULL)
//		OPENSSL_free(bufaux);
//	return ret;
//err:
//	if( bufaux != NULL)
//		OPENSSL_free(bufaux);
//	return 0;
}

int X509attr_IetfAttrSyntax_add_value( X509_ATTRIBUTE *attr, IetfAttrSyntax *val )
{
	int	enc_length = 0, ret=0;
	char* bufaux = NULL;
	char* p = NULL;
	char** pp = NULL;
	int attrtype;

	if( attr == NULL)
		return(0);

	enc_length = i2d_IetfAttrSyntax(val, NULL);

	if( (bufaux = (char*)OPENSSL_malloc(enc_length)) == NULL)
		goto err;

	p = bufaux;
	pp = &p;

	i2d_IetfAttrSyntax(val, (unsigned char**)pp);
	attrtype = V_ASN1_SEQUENCE;
	ret = X509attr_attribute_add_value(attr,attrtype,bufaux,enc_length);
	if( bufaux != NULL)
		OPENSSL_free(bufaux);
	return ret;
err:
	if( bufaux != NULL)
		OPENSSL_free(bufaux);
	return 0;
}

int X509attr_RoleSyntax_add_value( X509_ATTRIBUTE *attr, RoleSyntax *val )
{
	int	enc_length = 0, ret=0;
	char* bufaux = NULL;
	char* p = NULL;
	char** pp = NULL;
	int attrtype;

	if( attr == NULL)
		return(0);

	enc_length = i2d_RoleSyntax(val, NULL);

	if( (bufaux = (char*)OPENSSL_malloc(enc_length)) == NULL)
		goto err;

	p = bufaux;
	pp = &p;

	i2d_RoleSyntax(val, (unsigned char**)pp);
	attrtype = V_ASN1_SEQUENCE;
	ret = X509attr_attribute_add_value(attr,attrtype,bufaux,enc_length);
	if( bufaux != NULL)
		OPENSSL_free(bufaux);
	return ret;
err:
	if( bufaux != NULL)
		OPENSSL_free(bufaux);
	return 0;
}
int X509attr_Clearance_add_value( X509_ATTRIBUTE *attr, Clearance *val)
{

	return 0;
}


