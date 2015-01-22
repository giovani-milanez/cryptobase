/* Written by Markus Lorch (mlorch@vt.edu) 
 * Supplemental routines for OpenSSL attribute certificate support *
 */

#include "cryptobase/x509attr.h"
#include "cryptobase/x509ac.h"
#include "cryptobase/x509ac-supp.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

/* needed for debugging output to stderr */
#include <stdio.h>
#include <time.h>

void handle_error (const char *file, int lineno, const char *msg)
{
	fprintf (stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp (stderr);
	exit (-1);
}

/* compose a base cert ID from an X509 certificate */

X509AC_ISSUER_SERIAL* X509_get_basecertID(X509 *x)
{
	X509AC_ISSUER_SERIAL *basecertid = NULL;
	GENERAL_NAMES *gens;
	GENERAL_NAME *gen;

	if(x==NULL)
		return(NULL);

	basecertid = X509AC_ISSUER_SERIAL_new();
	/* extract base cert id form holder
		cert and input to attribute cert */

	gens = basecertid->issuer;
	gen = GENERAL_NAME_new();
	gen->type = GEN_DIRNAME;
	gen->d.directoryName = X509_NAME_dup(x->cert_info->issuer);
	sk_GENERAL_NAME_insert( gens, 0, 0 );
	sk_GENERAL_NAME_set(gens, 0, gen);

	if( basecertid->serial != NULL )
	{
		ASN1_INTEGER_free(basecertid->serial);
		basecertid->serial = ASN1_INTEGER_dup(x->cert_info->serialNumber);
		//ASN1_INTEGER_set(basecertid->serial,ASN1_INTEGER_get(holder_cert->cert_info->serialNumber));
	}
	else
		basecertid->serial = ASN1_INTEGER_dup(x->cert_info->serialNumber);

	return basecertid;
}
/***********************************************************
 * utility functions to handle X.509 attribute certificates
 */


/* This function will return the first X500 directory name it can
	find in the issuer generalNames section of an AC, null if none is found */

X509_NAME *X509AC_get_issuer_name(X509AC *a)
{
	X509_NAME *ret = NULL;
	GENERAL_NAMES *gens = NULL;
	GENERAL_NAME *gen = NULL;
	int i;


	if(a->info->issuer->type==0) {   // v1Form
		gens = a->info->issuer->d.v1Form;
	}
	else { // v2Form
		if( a->info->issuer->d.v2Form->issuer != NULL)
			gens = a->info->issuer->d.v2Form->issuer;
	}

	/* find the first directory name */

	for (i=0;i < sk_GENERAL_NAME_num(gens); i++)
	{
		gen = sk_GENERAL_NAME_value(gens, i);
		if(gen->type == GEN_DIRNAME) {
			ret = gen->d.directoryName;  // d will contain a X509_NAME (directoryName)
			break;
		}
	}
	return ret;
}

/* This function will return the first X500 directory name it can
	find in the holder generalNames section of an AC, null if none is found */
X509_NAME *X509AC_get_holder_entity_name(X509AC *a)
{
	X509_NAME *ret = NULL;
	GENERAL_NAMES *gens = NULL;
	GENERAL_NAME *gen = NULL;
	int i;

	gens = a->info->holder->entity;

	/* find the first directory name */

	for (i=0;i < sk_GENERAL_NAME_num(gens); i++)
	{
		gen = sk_GENERAL_NAME_value(gens, i);
		if(gen->type == GEN_DIRNAME) {
			ret = gen->d.directoryName;  // d will contain a X509_NAME (directoryName)
			break;
		}
	}
	return ret;
}
X509AC_ISSUER_SERIAL *X509AC_get_holder_baseCertID(X509AC *a)
{
	return a->info->holder->baseCertID;
}
ASN1_BIT_STRING *X509AC_get_holder_objectDigestInfo(X509AC *a)
{
	return (ASN1_BIT_STRING*) a->info->holder->objectDigestInfo;
}
X509AC_ISSUER_SERIAL *X509AC_get_issuer_baseCertID(X509AC *a)
{
	if((a == NULL)||(a->info->issuer->type == 0))
		return NULL;
	return a->info->issuer->d.v2Form->baseCertID;
}
ASN1_BIT_STRING *X509AC_get_issuer_objectDigestInfo(X509AC *a)
{
	if((a == NULL)||(a->info->issuer->type == 0))
		return NULL;
	return (ASN1_BIT_STRING*) a->info->issuer->d.v2Form->digest;
}
long X509AC_get_version(X509AC *a)
{
	if(( a == NULL))
		return -1;
	return ASN1_INTEGER_get(a->info->version);
}

/* Set functions */
/* This set the version of the AC, this version affects also to the issuer form */
int X509AC_set_version(X509AC *a, long version)
{
	if (a == NULL) return(0);
	if (a->info->version == NULL)
	{
		if ((a->info->version = M_ASN1_INTEGER_new()) == NULL)
			return(0);
	}

	// Added by  Felipe Menegola Blauth:
	// Modifiquei essa parte para o seguinte: 1 significa v2 e 0 significa v1 (estava 2 para v2 e 1 para v1)
	if(version == 0)
	{
		a->info->issuer->type = 0;
		return(ASN1_INTEGER_set(a->info->version, 0));
	}
	else if(version == 1)
	{
		a->info->issuer->type = 1;
		return(ASN1_INTEGER_set(a->info->version, 1));
	}
	return(0);
}

/* set the holder name in the entity name of holder */

int X509AC_set_holder_entity_name(X509AC* a, X509_NAME *name)
{
	// TODO implement
	return 0;
//	GENERAL_NAME *gen;
//
//	if( (a == NULL)||(name == NULL) )
//		return(0);
//	if( a->info->holder == NULL )
//		a->info->holder = X509AC_HOLDER_new();
//	if( a->info->holder->entity == NULL)
//		a->info->holder->entity = GENERAL_NAMES_new();
//	gen = GENERAL_NAME_new();
//	gen->type = GEN_DIRNAME;
//	gen->d.directoryName = name;
//	sk_GENERAL_NAME_insert( a->info->holder->entity, 0, 0 );
//	sk_GENERAL_NAME_set(a->info->holder->entity, 0, gen);
}

/*
 * this set the holder name in the basecert ID space of the att cert
 */
int X509AC_set_holder_name(X509AC* a, X509_NAME *name)
{
	if ((a == NULL)||(name == NULL))
		return(0);
	if( a->info->holder == NULL )
		a->info->holder = X509AC_HOLDER_new();
	if( a->info->holder->baseCertID == NULL )
	{
		a->info->holder->baseCertID = X509AC_ISSUER_SERIAL_new();
	}
	if( a->info->holder->baseCertID->issuer == NULL)
		a->info->holder->baseCertID->issuer = GENERAL_NAMES_new();
	/*		else
		{
		X509AC_ISSUER_SERIAL_new(a->info->holder->baseCertID);	
		a->info->holder->baseCertID = X509AC_ISSUER_SERIAL_new();
		}
	 */

	return X509AC_set_GENERAL_NAME_name( a->info->holder->baseCertID->issuer, name);
}

int X509AC_set_holder_serialNumber(X509AC *x, ASN1_INTEGER *serial)
{
	ASN1_INTEGER *in;

	if (x == NULL) return(0);
	in = x->info->holder->baseCertID->serial;

	if (in != serial)
	{
		in = M_ASN1_INTEGER_dup(serial);
		if (in != NULL)
		{
			M_ASN1_INTEGER_free(x->info->holder->baseCertID->serial);
			x->info->holder->baseCertID->serial=in;
		}
	}
	return(in != NULL);
}
/*
 * Set holder baseCertID
 */
int X509AC_set_holder_baseCertID(X509AC* a, X509AC_ISSUER_SERIAL *bci)
{
	X509AC_ISSUER_SERIAL *aux = NULL;
	if( (a == NULL)||(bci == NULL) )
		return(0);
	if( a->info->holder == NULL)
		return(0);
	if(a->info->holder->baseCertID != NULL)
		X509AC_ISSUER_SERIAL_free(a->info->holder->baseCertID);
	//a->info->holder->baseCertID = in;
	aux = bci;
	a->info->holder->baseCertID = (X509AC_ISSUER_SERIAL *) X509AC_ISSUER_SERIAL_dup(aux);
	return(a->info->holder->baseCertID!=NULL);
}

int X509AC_set_holder_objectDigestInfo(X509AC *a, X509AC_OBJECT_DIGESTINFO *odig)
{
	// TODO implement
	return 0;
}
/*
 * Set issuer objectDigestInfo
 */
int X509AC_set_issuer_objectDigestInfo(X509AC* a, X509AC_OBJECT_DIGESTINFO *odig)
{
	// TODO implement
	return 0;
}

/*
 * Set issuer baseCertID
 */
int X509AC_set_issuer_baseCertID(X509AC* a, X509AC_ISSUER_SERIAL *bci)
{
	X509AC_ISSUER_SERIAL *aux;
	long ver = 0;
	if( (a == NULL)||(bci == NULL) )
		return(0);

	ver = ASN1_INTEGER_get(a->info->version);

	if( ver != 2)
		return(0);
	if(!a->info->issuer->d.v2Form)
		a->info->issuer->d.v2Form = X509AC_V2FORM_new();

	if(a->info->issuer->d.v2Form->baseCertID != NULL)
		X509AC_ISSUER_SERIAL_free(a->info->issuer->d.v2Form->baseCertID);
	aux = bci;
	a->info->issuer->d.v2Form->baseCertID = (X509AC_ISSUER_SERIAL *) X509AC_ISSUER_SERIAL_dup(aux);

	return(a->info->issuer->d.v2Form->baseCertID != NULL);
}

/*
 * this set the issuer name. Depending on the version it will set d.v1Form
 * or d.v2Form->issuer GENERAL_NAMES structure
 */
int X509AC_set_issuer_name(X509AC* a, X509_NAME *name)
{

	long ver = 0;

	if ((a == NULL)||(name == NULL)) return(0);

	if( a->info->issuer == NULL )
		return(0);

	/* check version */
	ver = ASN1_INTEGER_get(a->info->version);

	// Eu (Felipe Blauth) modifiquei essa parte para o seguinte: 1 significa v2 e 0 significa v1 (estava 2 para v2 e 1 para v1)
	if(ver == 1)
	{
		if( a->info->issuer->d.v2Form == NULL )
			a->info->issuer->d.v2Form = X509AC_V2FORM_new();
		if( a->info->issuer->d.v2Form->issuer == NULL)
			a->info->issuer->d.v2Form->issuer = GENERAL_NAMES_new();
		return X509AC_set_GENERAL_NAME_name(a->info->issuer->d.v2Form->issuer,name);
	}
	else if(ver == 0)
	{
		if( a->info->issuer->d.v1Form == NULL)
			return(0);
		return X509AC_set_GENERAL_NAME_name(a->info->issuer->d.v1Form,name);
	}
	return(0);
}

int X509AC_set_GENERAL_NAME_name(GENERAL_NAMES *gens, X509_NAME *name)
{
	GENERAL_NAME* gen;

	if( (name == NULL) )
		return(0);
	if (gens == NULL)
		gens = GENERAL_NAMES_new();

	if (gens != NULL)
	{
		gen = GENERAL_NAME_new();
		gen->type = GEN_DIRNAME;
		gen->d.directoryName = X509_NAME_new();
		/* set the value in aux */
		if(!X509AC_X509_NAME_dup(&(gen->d.directoryName),name))
		{
			GENERAL_NAME_free(gen);
			return 0;
		}
		/* introduce genral name in the seq */
		sk_GENERAL_NAME_insert(gens,gen,0);
		sk_GENERAL_NAME_set(gens,0,gen);
		//			GENERAL_NAME_free(gen);
		return 1;
	}
	return 0;

}

int X509AC_set_baseCertID_name(X509AC_ISSUER_SERIAL *bci, X509_NAME *name)
{
	GENERAL_NAMES* gens;
	GENERAL_NAME* gen;

	if( (bci == NULL)||(name == NULL) )
		return(0);

	gens = bci->issuer;
	/* new general name (aux)*/
	if (gens != NULL)
	{
		gen = GENERAL_NAME_new();
		gen->type = GEN_DIRNAME;
		gen->d.directoryName = X509_NAME_new();
		/* set the value in aux */
		if(!X509AC_X509_NAME_dup(&(gen->d.directoryName),name))
		{
			GENERAL_NAME_free(gen);
			return 0;
		}
		/* introduce genral name in the seq */
		sk_GENERAL_NAME_insert(gens,gen,0);
		sk_GENERAL_NAME_set(gens,0,gen);
		GENERAL_NAME_free(gen);
		return 1;
	}
	return 0;

}

int X509AC_set_baseCertID_serial(X509AC_ISSUER_SERIAL *bci, ASN1_INTEGER *serial)
{
	ASN1_INTEGER *aux, *in;

	if( (bci == NULL)||(serial == NULL) )
		return(0);

	in = bci->serial;
	aux = serial;

	if( in == NULL)
	{
		in = ASN1_INTEGER_dup(aux);
		return( bci->serial != NULL );
	}
	else
		return ASN1_INTEGER_set(in,ASN1_INTEGER_get(aux));
}

int X509AC_set_baseCertID_issuerUniqueID(X509AC_ISSUER_SERIAL *bci, ASN1_BIT_STRING *uid)
{
	ASN1_BIT_STRING *in, *aux;

	if( (bci == NULL)||(uid == NULL) )
		return(0);

	in = bci->issuerUniqueID;
	aux = uid;

	if( in == NULL)
	{
		in = ASN1_BIT_STRING_new();
		return ASN1_BIT_STRING_set(in,aux->data,aux->length);
	}
	else
		return ASN1_BIT_STRING_set(in,aux->data,aux->length);
}

/* this function retreives an attribute certificate
	in the position idx */

X509_ATTRIBUTE * X509AC_get_attr( X509AC *a, int idx )
{
	if( a == NULL)
		return NULL;
	if( idx> X509AC_get_attributecount(a) )
		return NULL;
	return X509at_get_attr( a->info->attributes, idx);
}

/* These functions add a X509_ATTRIBUTE to the certificate */
int X509AC_add_attribute(X509AC *a, X509_ATTRIBUTE *attr)
{
	if( (a == NULL) || (attr == NULL) )
		return(0);
	return X509AC_add_X509_ATTRIBUTE(a, attr);
}

int X509AC_add_attribute_by_NID(X509AC *a,
		int nid, int atrtype, void *value)
{
	X509_ATTRIBUTE *attr =NULL;
	STACK_OF(X509_ATTRIBUTE) *psk = NULL;
	STACK_OF(X509_ATTRIBUTE) **ppsk = NULL;
	int i = 0;

	if(a == NULL)
		return(0);

	psk = a->info->attributes;
	ppsk = &psk;
	if (*ppsk == NULL)
	{
		*ppsk = sk_X509_ATTRIBUTE_new_null();
		new_attrib:
		attr = X509_ATTRIBUTE_create( nid, atrtype, value );
		sk_X509_ATTRIBUTE_push( *ppsk, attr );
	}
	else
	{

		for (i=0; i<sk_X509_ATTRIBUTE_num(*ppsk); i++)
		{
			attr = sk_X509_ATTRIBUTE_value( *ppsk, i );
			if (OBJ_obj2nid( attr->object ) == nid)
			{
				X509_ATTRIBUTE_free( attr );
				attr=X509_ATTRIBUTE_create( nid, atrtype, value);
				sk_X509_ATTRIBUTE_set( *ppsk, i, attr);
				goto end;
			}
		}
		goto new_attrib;
	}
	end:
	return(1);
}

int X509AC_sign_rsa(X509AC *a, RSA *rsa, EVP_MD *md)
{
	EVP_PKEY *pkey = NULL;
	int len = 0;

	if( a == NULL)
		return(0);
	if( rsa == NULL)
		return(0);

	pkey= EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey,rsa);

	len = ASN1_sign( (i2d_of_void*) i2d_X509AC_INFO, a->info->algor,
			a->algor,a->signature,(char*)a->info, pkey,md);

	return len;

}

int X509AC_sign_pkey(X509AC *a, EVP_PKEY *pkey, EVP_MD *md)
{
	int len = 0;

	if( a == NULL)
		return(0);
	if( pkey == NULL)
		return(0);

	len = ASN1_sign( (i2d_of_void*)i2d_X509AC_INFO, a->info->algor,
			a->algor,a->signature,(char*)a->info, pkey, md);

	return len;
}

ASN1_TYPE *X509AC_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx)
{
	if (attr == NULL) return(NULL);
	if(idx >= X509_ATTRIBUTE_count(attr)) return NULL;
	if(!attr->single) return sk_ASN1_TYPE_value(attr->value.set, idx);
	else return attr->value.single;
}

void *X509AC_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx,
		int atrtype, void *data)
{
	ASN1_TYPE *ttmp;
	ttmp = X509AC_ATTRIBUTE_get0_type(attr, idx);
	if(!ttmp) return NULL;
	if(atrtype != ASN1_TYPE_get(ttmp)){
		//X509err(X509_F_X509_ATTRIBUTE_GET0_DATA, X509_R_WRONG_TYPE);
		return NULL;
	}
	return ttmp->value.ptr;
}

int X509AC_add_X509_ATTRIBUTE(X509AC *a, X509_ATTRIBUTE *attr)
{
	X509_ATTRIBUTE *new_attr;
	STACK_OF(X509_ATTRIBUTE) *psk = NULL;
	STACK_OF(X509_ATTRIBUTE) **ppsk = NULL;

	if(a == NULL)
		return(0);

	psk = a->info->attributes;
	ppsk = &psk;
	if (*ppsk == NULL)
	{
		*ppsk = sk_X509_ATTRIBUTE_new_null();
		new_attrib:
		new_attr = attr;//X509_ATTRIBUTE_dup(attr);
		sk_X509_ATTRIBUTE_push( *ppsk, new_attr );
		//sk_X509_ATTRIBUTE_insert( *ppsk, new_attr,i);
	}
	else
	{
		//			for (i=0; i<sk_X509_ATTRIBUTE_num(*ppsk); i++)
		//			{
		//				attr_aux = sk_X509_ATTRIBUTE_value( *ppsk, i );
		//				if (OBJ_obj2nid( attr_aux->object ) == OBJ_obj2nid( attr->object ))
		//				{
		//					X509_ATTRIBUTE_free( attr_aux );
		//					new_attr = X509_ATTRIBUTE_dup(attr);
		//					sk_X509_ATTRIBUTE_set( *ppsk, i, new_attr);
		//					goto end;
		//				}
		//			}
		goto new_attrib;
	}
	return(1);
}


int X509AC_get_attributecount(X509AC *a)
{
	if( a == NULL )
		return -1;
	return X509at_get_attr_count(a->info->attributes);
}
int X509AC_X509_NAME_dup(X509_NAME **xn, X509_NAME *name)
{
	X509_NAME *in;
	if (!xn || !name) return(0);
	if (*xn != name)
	{
		in = X509_NAME_dup(name);
		if (in != NULL)
		{
			X509_NAME_free(*xn);
			*xn=in;
		}
	}
	return(*xn != NULL);
}


/* this is a wrapper for the standard X509_verify_cert, which takes two parameters
	(1) a verify context that need not have the x509 cert to be verified set
	(2) the AC that shall be verified
	it works as follows
	- check AC time validity
	- try to find AC issuer in context
	- validate AC signature
	- call X509_verify_cert with the issuer certificate to complete path validation
 */
int X509AC_verify_cert(X509_STORE_CTX * verify_ctx, X509AC * ac, int verifyValidity, time_t trustedTime)
{
	int 		diff = 0;
	X509* 	issuer = NULL;
	X509_NAME *  acIssuer = NULL;
	int 		i = 0;
	EVP_PKEY *	pkey = NULL;

	if (verifyValidity)
	{
		/* ok, first do a validity time check */
		time_t tmp = trustedTime;
		diff = X509_cmp_time(ac->info->validity->notBefore, &tmp);
		if(diff == 0){
			return BAD_GENERALIZED_TIME_FIELD;
		}

		if(diff > 0) {
			return ATTRIBUTE_CERTIFICATE_NOT_VALID_YET;
		}

		tmp = trustedTime;
		diff = X509_cmp_time(ac->info->validity->notAfter, &tmp);
		if(diff == 0) {
			return BAD_GENERALIZED_TIME_FIELD;
		}
		if(diff < 0) {
			return ATTRIBUTE_CERTIFICATE_EXPIRED;
		}
	}
#ifdef DEBUG
	fprintf(stderr, "Attribute certificate validity period is ok \n");
#endif

	/* get the AC issuer name */
	acIssuer = X509AC_get_issuer_name(ac);
	if (!acIssuer) {
		return COULD_NOT_GET_AC_ISSUER;
	}


	/* now try to find AC issuer in untrusted chain of context */

#ifdef DEBUG
	fprintf(stderr, "Untrusted chain holds %i certs\n", sk_X509_num(verify_ctx->untrusted));
#endif

	for (i = 0; i < sk_X509_num(verify_ctx->untrusted); i++)
	{
		X509_NAME *  subject = NULL;
		char	  subject_name[128];

		issuer = sk_X509_value(verify_ctx->untrusted, i);

		if(!issuer) {
			fprintf(stderr,"Error getting cert from stack\n");
			return -1;
		}


		/* AC issuer name needs to match issuer cert subject */

		/* get the cert subject name (the possible issuer) */
		subject = X509_get_subject_name(issuer);
		if (!subject) {
			return COULD_NOT_GET_ISSUER_SUBJECT_NAME;
		}

#ifdef DEBUG     
		fprintf(stderr,"got issuer name from cert \n");
#endif

		X509_NAME_oneline(subject,subject_name,128);

#ifdef DEBUG     
		fprintf(stderr,"Issuer cert subject: %s \n", subject_name);
#endif

		if(X509_NAME_cmp(acIssuer, subject)==0) {
#ifdef DEBUG     
			fprintf(stderr, "Found issuer certificate \n");
#endif
			break; /* found it */
		}
		else {
			issuer = NULL;
		}

	} // end for

	if(!issuer) {
#ifdef DEBUG     
		fprintf(stderr, "Unable to find issuer certificate \n");
#endif

		return UNABLE_TO_FIND_ISSUER_CERT;
	}



	/* now verify the signature on the AC */

	pkey = X509_get_pubkey(issuer);

	if (pkey == NULL) {
		return ISSUER_PUB_KEY_NOT_FOUND;
	}


	if(pkey->type == EVP_PKEY_RSA)

#ifdef DEBUG 
		fprintf(stderr,"OK we got an RSA public key \n");
	fprintf(stderr,"key size =%i\n", EVP_PKEY_size(pkey));
	fprintf(stderr, "signature length= %i\n",ac->signature->length);
#endif

	if ((ASN1_item_verify(ASN1_ITEM_rptr(X509AC_INFO),ac->algor,
			ac->signature,ac->info,pkey)) <=0) {
		fprintf(stderr, "Error verifying AC signature\n");
		return INVALID_ATTRIBUTE_CERTIFICATE_SIGNATURE;
	}

#ifdef DEBUG 
	fprintf(stderr, "AC signature verified\n");
#endif

	/* alright now set the verify context to hold the located issuer cert */

	verify_ctx->cert=issuer;

	/* call the standard verify routine on the issuer cert */

	return X509_verify_cert(verify_ctx);

} // end X509AC_verify_cert



/* the following is a simple function that prints the contents
	of an AC to stderr, including if present attributes (undefined
	behavior if attribute data is not of type printablestring */
//void X509AC_print(X509AC *ac) {
//
//	X509_NAME *name;
//	char nameString[ONELINELEN];
//	int i, j, attr_count,k;
//	X509_ATTRIBUTE *attribute;
//	ASN1_TYPE *attr_type;
//	ASN1_PRINTABLESTRING *astring;
//	int nid = 0;
//	int type = 0;
//	SvceAuthInfo *svceauth = NULL;
//	IetfAttrSyntax *ietfattrsyntax = NULL;
//	RoleSyntax *role = NULL;
//	unsigned char *p=NULL,**pp=NULL;
//	X509_EXTENSION *ext = NULL;
//	BIO *bio;
//	ASN1_OBJECT *obj = NULL;
//	//int *attr_type_count;
//
//	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
//
//	fprintf(stdout,"AC Version= v%d, \n", ASN1_INTEGER_get(ac->info->version));
//
//	fprintf(stdout,"Issuer Information\n");
//	fprintf(stdout,"------------------\n\n");
//	if( (ac->info->issuer->type == 0)||
//			((ac->info->issuer->type == 1)&&(ac->info->issuer->d.v2Form->issuer != NULL)))
//	{
//		if( ASN1_INTEGER_get(ac->info->version) == 2)
//			fprintf(stdout,"Issuer Name (v2Form->issuer)\n");
//		else if( ASN1_INTEGER_get(ac->info->version) == 1)
//			fprintf(stdout,"Issuer Name (v1Form->issuer)\n");
//
//		name = X509AC_get_issuer_name(ac);
//		if (!name)
//			int_error ("Error getting AC issuer name, possibly not a X500 name");
//		else
//		{
//			X509_NAME_oneline(name,nameString,ONELINELEN);
//			fprintf (stdout, "AC Issuer: %s \n", nameString);
//		}
//
//	}
//	if(ac->info->issuer->d.v2Form->baseCertID != NULL)
//		X509AC_ISSUER_SERIAL_print(ac->info->issuer->d.v2Form->baseCertID);
//	fprintf(stdout,"Holder Information\n");
//	fprintf(stdout,"------------------\n\n");
//
//	if( ac->info->holder->entity != NULL)
//	{
//		name = X509AC_get_holder_entity_name(ac);
//		if (!name)
//			int_error ("Error getting AC holder name, possibly not a X500 name");
//		else
//		{
//			X509_NAME_oneline(name,nameString,ONELINELEN);
//			fprintf (stdout, "AC Holder: %s \n", nameString);
//		}
//	}
//	if( ac->info->holder->baseCertID != NULL)
//	{
//		printf("Holder BaseCertID:\n");
//		X509AC_ISSUER_SERIAL_print(ac->info->holder->baseCertID);
//	}
//
//	/* Validity Time */
//	fprintf(stdout,"Validity\n");
//	fprintf(stdout,"--------\n\n");
//	fprintf(stdout, "Valid not before: ");
//	for(i = 0; i < ac->info->validity->notBefore->length;i++)
//		fprintf(stdout,"%c",ac->info->validity->notBefore->data[i]);
//	fprintf(stdout, "\n");
//	fprintf(stdout, "Valid not after: ");
//	for(i = 0; i < ac->info->validity->notAfter->length;i++)
//		fprintf(stdout,"%c",ac->info->validity->notAfter->data[i]);
//	fprintf(stdout, "\n");
//
//	/* attributes */
//	fprintf(stdout, "Attribute information\n");
//	fprintf(stdout, "---------------------\n");
//	attr_count = X509at_get_attr_count(ac->info->attributes);
//	if (attr_count>0)
//	{
//		fprintf(stdout,"Number of attributes: %i \n\n", attr_count);
//		//attr_type_count = OPENSSL_malloc(2*attr_count*sizeof(int));
//		//for(i=0;i<(2*attr_count);i++)
//		//	attr_type_count[i]=0;
//	}
//	else
//		fprintf(stdout, "No attributes present \n");
//
//	/* iterate through attributes */
//	for(i=0;i<attr_count;i++)
//	{
//		fprintf(stdout, "\tAttribute Number: %i\n",i);
//		fprintf(stdout, "\t--------------------\n");
//		attribute = X509at_get_attr(ac->info->attributes,i);
//		nid = OBJ_obj2nid(attribute->object);
//		fprintf(stdout, "\tAttribute NID: %d , Name: %s \n",nid, OBJ_nid2ln(nid));
//
//		if( nid == NID_id_aca_authenticationInfo )
//		{
//			fprintf(stdout, "\tService Authentication Information\n");
//			fprintf(stdout, "\tAttribute syntax SvceAuthInfo\n");
//			fprintf(stdout, "\tConsumed by the target application not the AC verifier\n");
//			fprintf(stdout, "\tMultiple values allowed : yes\n");
//			fprintf(stdout, "\tValues: %d\n",sk_ASN1_TYPE_num(attribute->value.set));
//
//			for(k=0;k<sk_ASN1_TYPE_num(attribute->value.set);k++)
//			{
//				fprintf(stdout, "\t\tPrinting value: %d\n",k);
//				fprintf(stdout, "\t\t------------------\n");
//				attr_type = sk_ASN1_TYPE_value(attribute->value.set,k/*0*/);
//				p = attr_type->value.sequence->data;
//				pp = &p;
//				svceauth = d2i_SvceAuthInfo(NULL,(const unsigned char**)pp ,attr_type->value.sequence->length);
//				if(svceauth==NULL)
//				{
//					fprintf(stdout, "\t\t**** ERROR **** Not possible to parse attr\n ");
//					continue;
//				}
//				fprintf(stdout, "\t\tIdent information : ");
//				if(svceauth->ident != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAME_pprinter(stdout, svceauth->ident);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tService information : ");
//				if(svceauth->service != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAME_pprinter(stdout, svceauth->service);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tAuth Info : ");
//				if(svceauth->authInfo != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					for(j=0;j<svceauth->authInfo->length;j++)
//						fprintf (stdout,"0x%.2x:", astring->data[j]);
//				}
//				else
//					fprintf(stdout, "Not present\n");
//				if(svceauth != NULL)
//					SvceAuthInfo_free(svceauth);
//			}
//		}
//		else if(nid == NID_id_aca_accessIdentity)
//		{
//			fprintf(stdout, "\tAccess Identity\n");
//			fprintf(stdout, "\tAttribute syntax SvceAuthInfo without AuthInfo\n");
//			fprintf(stdout, "\tConsumed by the AC verifier to authorise\n");
//			fprintf(stdout, "\tMultiple values allowed : yes\n");
//			fprintf(stdout, "\tValues: %d\n",sk_ASN1_TYPE_num(attribute->value.set));
//			for(k=0;k<sk_ASN1_TYPE_num(attribute->value.set);k++)
//			{
//				//attr_type = X509_ATTRIBUTE_get0_type(attribute,k);
//				attr_type = sk_ASN1_TYPE_value(attribute->value.set,k/*0*/);
//				fprintf(stdout, "\t\tPrinting value: %d\n",k);
//				fprintf(stdout, "\t\t------------------\n");
//
//				p = attr_type->value.sequence->data;
//				pp = &p;
//				svceauth = d2i_SvceAuthInfo( NULL, (const unsigned char**)pp ,attr_type->value.sequence->length);
//				if(svceauth==NULL)
//				{
//					fprintf(stdout, "\t\t**** ERROR **** Not possible to parse attr\n ");
//					continue;
//				}
//				fprintf(stdout, "\t\tIdent information : ");
//				if(svceauth->ident != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAME_pprinter(stdout, svceauth->ident);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tService information : ");
//				if(svceauth->service != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAME_pprinter(stdout, svceauth->service);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tAuth Info : ");
//				if(svceauth->authInfo != NULL)
//				{
//					fprintf(stdout, "Present\n");
//					fprintf(stdout, "\t\t...is an error! it should not be present\n");
//				}
//				else
//					fprintf(stdout, "Not present... it should be not present!\n");
//				if(svceauth != NULL)
//					SvceAuthInfo_free(svceauth);
//			}
//		}
//		else if(nid == NID_id_aca_chargingIdentity)
//		{
//			fprintf(stdout, "\tCharging Identity\n");
//			fprintf(stdout, "\tAttribute syntax IetfAttrSyntax\n");
//			fprintf(stdout, "\tConsumed by the AC verifier to authorise\n");
//			fprintf(stdout, "\tMultiple values allowed : no\n");
//			fprintf(stdout, "\tValues: %d\n",sk_ASN1_TYPE_num(attribute->value.set));
//			if(sk_ASN1_TYPE_num(attribute->value.set)>1)
//				fprintf(stdout, "\tMultiple values not allowed : attribute not correct\n");
//			for(k=0;k<sk_ASN1_TYPE_num(attribute->value.set);k++)
//			{
//				//attr_type = X509_ATTRIBUTE_get0_type(attribute,k);
//				attr_type = sk_ASN1_TYPE_value(attribute->value.set,k/*0*/);
//				fprintf(stdout, "\t\tPrinting value: %d\n",k);
//				fprintf(stdout, "\t\t------------------\n");
//
//				p = attr_type->value.sequence->data;
//				pp = &p;
//				ietfattrsyntax = d2i_IetfAttrSyntax(NULL,(const unsigned char**)pp ,attr_type->value.sequence->length);
//				if(ietfattrsyntax == NULL)
//				{
//					fprintf(stdout, "\t\t**** ERROR **** Not possible to parse attr\n ");
//					continue;
//				}
//				fprintf(stdout, "\t\tPolicy Authority information : ");
//				if(ietfattrsyntax->policyAuthority != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAMES_pprinter(stdout, ietfattrsyntax->policyAuthority);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tType of info :  ");
//				if(ietfattrsyntax->type != V_ASN1_OCTET_STRING )
//				{
//					fprintf(stdout, "V_ASN1_OCTET_STRING\n\t\t");
//					for(j=0; j<ietfattrsyntax->values.octets->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.octets->data[j]);
//					fprintf(stdout, "\n");
//				}
//				else if(ietfattrsyntax->type != V_ASN1_UTF8STRING )
//				{
//					fprintf(stdout, "V_ASN1_UTF8STRING\n\t\t");
//					for(j=0;j<ietfattrsyntax->values.string->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.string->data[j]);
//					fprintf(stdout, "\n");
//				}
//				else if(ietfattrsyntax->type != V_ASN1_OBJECT )
//				{
//					fprintf(stdout, "V_ASN1_OBJECT\n\t\t");
//					for(j=0;j<ietfattrsyntax->values.string->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.string->data[j]);
//					fprintf(stdout, "\n");
//				}else
//				{
//					fprintf(stdout, "*** ERROR **** : Info Unknown\n");
//				}
//				if(ietfattrsyntax != NULL)
//				{
//					IetfAttrSyntax_free(ietfattrsyntax);
//				}
//			} //end for
//		}
//		else if(nid == NID_id_aca_group)
//		{
//			fprintf(stdout, "\tGroup Memberships\n");
//			fprintf(stdout, "\tAttribute syntax IetfAttrSyntax\n");
//			fprintf(stdout, "\tConsumed by the AC verifier to authorise\n");
//			fprintf(stdout, "\tMultiple values allowed : no\n");
//			fprintf(stdout, "\tValues: %d\n",sk_ASN1_TYPE_num(attribute->value.set));
//			if(sk_ASN1_TYPE_num(attribute->value.set)>1)
//				fprintf(stdout, "\tMultiple values not allowed : attribute not correct\n");
//			for(k=0;k<sk_ASN1_TYPE_num(attribute->value.set);k++)
//			{
//				attr_type = sk_ASN1_TYPE_value(attribute->value.set,k/*0*/);
//				//attr_type = X509_ATTRIBUTE_get0_type(attribute,k);
//				fprintf(stdout, "\t\tPrinting value: %d\n",k);
//				fprintf(stdout, "\t\t------------------\n");
//
//				p = attr_type->value.sequence->data;
//				pp = &p;
//				ietfattrsyntax = d2i_IetfAttrSyntax(NULL,(const unsigned char**)pp ,attr_type->value.sequence->length);
//				if(ietfattrsyntax == NULL)
//				{
//					fprintf(stdout, "\t\t**** ERROR **** Not possible to parse attr\n ");
//					continue;
//				}
//				fprintf(stdout, "\t\tPolicy Authority information : ");
//				if(ietfattrsyntax->policyAuthority != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAMES_pprinter(stdout, ietfattrsyntax->policyAuthority);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\tType of info :  ");
//				if(ietfattrsyntax->type != V_ASN1_OCTET_STRING )
//				{
//					fprintf(stdout, "V_ASN1_OCTET_STRING\n\t\t");
//					for(j=0; j<ietfattrsyntax->values.octets->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.octets->data[j]);
//					fprintf(stdout, "\n");
//				}
//				else if(ietfattrsyntax->type != V_ASN1_UTF8STRING )
//				{
//					fprintf(stdout, "V_ASN1_UTF8STRING\n\t\t");
//					for(j=0;j<ietfattrsyntax->values.string->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.string->data[j]);
//					fprintf(stdout, "\n");
//				}
//				else if(ietfattrsyntax->type != V_ASN1_OBJECT )
//				{
//					fprintf(stdout, "V_ASN1_OBJECT\n\t\t");
//					for(j=0;j<ietfattrsyntax->values.string->length;j++)
//						fprintf(stdout,"0x%.2x",ietfattrsyntax->values.string->data[j]);
//					fprintf(stdout, "\n");
//				}else
//				{
//					fprintf(stdout, "*** ERROR **** : Info Unknown\n");
//				}
//				if(ietfattrsyntax != NULL)
//				{
//					IetfAttrSyntax_free(ietfattrsyntax);
//				}
//			} //end for
//		}
//		else if(nid == NID_role)
//		{
//			fprintf(stdout, "\tRole\n");
//			fprintf(stdout, "\tAttribute syntax RoleSyntax\n");
//			fprintf(stdout, "\tConsumed by the AC verifier\n");
//			fprintf(stdout, "\tMultiple values allowed : yes\n");
//			fprintf(stdout, "\tValues: %d\n",sk_ASN1_TYPE_num(attribute->value.set));
//			if(sk_ASN1_TYPE_num(attribute->value.set)>1)
//				fprintf(stdout, "\tMultiple values not allowed : attribute not correct\n");
//			for(k=0;k<sk_ASN1_TYPE_num(attribute->value.set);k++)
//			{
//				//attr_type = X509_ATTRIBUTE_get0_type(attribute,k);
//				attr_type = sk_ASN1_TYPE_value(attribute->value.set,k/*0*/);
//				fprintf(stdout, "\t\tPrinting value: %d\n",k);
//				fprintf(stdout, "\t\t------------------\n");
//
//				p = attr_type->value.sequence->data;
//				pp = &p;
//				role = d2i_RoleSyntax(NULL,(const unsigned char**)pp ,attr_type->value.sequence->length);
//				if(role == NULL)
//				{
//					fprintf(stdout, "\t\t**** ERROR **** Not possible to parse attr\n ");
//					continue;
//				}
//				fprintf(stdout, "\t\troleAuthority [Optional] : ");
//				if(role->roleAuthority != NULL)
//				{
//					fprintf(stdout, "Present\n\t\t");
//					GENERAL_NAMES_pprinter(stdout, role->roleAuthority);
//					fprintf(stdout, "\n");
//				}
//				else
//				{
//					fprintf(stdout, "Not present\n");
//				}
//				fprintf(stdout, "\t\troleName [MUST|URN]:  ");
//				if(role->roleName != NULL )
//				{
//					GENERAL_NAME_pprinter(stdout,role->roleName);
//					if(role->roleName->type != GEN_URI)
//						fprintf(stdout, "**** ERROR **** Not an URI [RFC3281]\n");
//					fprintf(stdout, "\n");
//				}
//				if(role != NULL)
//				{
//					RoleSyntax_free(role);
//				}
//			} //end for
//		}
//		else
//		{
//			fprintf(stdout, "First attribute field holds: \n");
//			astring = (ASN1_PRINTABLESTRING *)X509_ATTRIBUTE_get0_data(attribute,0,ASN1_TYPE_get(attr_type),NULL);
//			for(j=0;j<astring->length;j++) fprintf (stdout,"0x%.2x:", astring->data[j]);
//		}
//
//	} /* end for*/
//	fprintf(stdout,"\nExtensions:\n");
//	fprintf(stdout, "------------\n");
//	fprintf(stdout, "Number of extensions present : %d\n",sk_X509_EXTENSION_num(ac->info->extensions));
//	for(i = 0; i<sk_X509_EXTENSION_num(ac->info->extensions);i++)
//	{
//		ext = sk_X509_EXTENSION_value(ac->info->extensions,i);
//		obj = X509_EXTENSION_get_object(ext);
//		fprintf(stdout, "\tNID: %d, %s\n",OBJ_obj2nid(obj),OBJ_nid2ln(OBJ_obj2nid(obj)));
//		fprintf(stdout, "\tCritical: %s\n",(ext->critical==0xFF)?"Yes":"No");
//		fprintf(stdout, "\tData:");
//		for(j = 0; j<ext->value->length;j++)
//			fprintf(stdout,"%.2x:",ext->value->data[j]);
//		fprintf(stdout, "\n");
//	}
//	fprintf(stdout, "\nSignature:\n");
//	fprintf(stdout, "------------\n");
//	if(!X509_signature_print( bio, ac->algor, ac->signature))
//		fprintf(stdout,"Unable to print signature info\n");
//	fprintf(stdout,"\n------------------------\n\n");
//
//
//} /* end X509AC_print */
//int X509AC_ISSUER_SERIAL_print(X509AC_ISSUER_SERIAL *bci)
//{
//	int i =0;
//	fprintf(stdout,"\n\t->name(GNs):");
//	GENERAL_NAMES_pprinter(stdout, bci->issuer);
//	fprintf(stdout,"\n\t->serial(INT):");
//	for(i =0; i< bci->serial->length; i++)
//	{
//		if((i!=0)&&(i%ONELINELEN)==0)
//			fprintf(stdout,"\n");
//		fprintf(stdout,"%.2x:",bci->serial->data[i]);
//	}
//	fprintf(stdout,"\n\t->issuerUniqueID(INT):");
//	if(bci->issuerUniqueID !=0)
//		for(i =0; i< bci->issuerUniqueID->length; i++)
//		{
//			if((i%ONELINELEN)==0)
//				fprintf(stdout,"\n");
//			fprintf(stdout,"%.2x:",bci->issuerUniqueID->data[i]);
//		}
//	else
//		fprintf(stdout,"NULL\n");
//
//}
//int GENERAL_NAMES_pprinter(FILE *out, GENERAL_NAMES *gens)
//{
//	int i = 0;
//	GENERAL_NAME *gen;
//	for(i = 0; i<sk_GENERAL_NAME_num(gens);i++)
//	{
//		gen = sk_GENERAL_NAME_value(gens, i);
//		GENERAL_NAME_pprinter( out, gen );
//	}
//	return 1;
//}
//int GENERAL_NAME_pprinter(FILE *out, GENERAL_NAME *gen)
//{
//	unsigned char *p;
//	int i;
//	switch (gen->type)
//	{
//	case GEN_OTHERNAME:
//		fprintf( out, "othername:<unsupported>");
//		break;
//
//	case GEN_X400:
//		fprintf( out, "X400Name:<unsupported>");
//		break;
//
//	case GEN_EDIPARTY:
//		/* Maybe fix this: it is supported now */
//		fprintf( out, "EdiPartyName:<unsupported>");
//		break;
//
//	case GEN_EMAIL:
//		fprintf( out, "email:%s",gen->d.ia5->data);
//		break;
//
//	case GEN_DNS:
//		fprintf( out, "DNS:%s",gen->d.ia5->data);
//		break;
//
//	case GEN_URI:
//		fprintf( out, "URI:%s",gen->d.ia5->data);
//		break;
//
//	case GEN_DIRNAME:
//		fprintf( out, "DirName: ");
//		fprintf(stdout, X509_NAME_oneline(gen->d.dirn,NULL,0));
//		//X509_NAME_print_ex(out, gen->d.dirn, 0, XN_FLAG_ONELINE);
//		break;
//
//	case GEN_IPADD:
//		p = gen->d.ip->data;
//		if(gen->d.ip->length == 4)
//			fprintf( out, "IP Address:%d.%d.%d.%d",
//					p[0], p[1], p[2], p[3]);
//		else if(gen->d.ip->length == 16)
//		{
//			fprintf( out, "IP Address");
//			for (i = 0; i < 8; i++)
//			{
//				fprintf( out, ":%X", p[0] << 8 | p[1]);
//				p += 2;
//			}
//			fprintf( out, "\n");
//		}
//		else
//		{
//			fprintf( out,"IP Address:<invalid>");
//			break;
//		}
//		break;
//
//	case GEN_RID:
//		fprintf( out, "Registered ID");
//		i2a_ASN1_OBJECT((BIO*)out, gen->d.rid);
//		break;
//	}
//	return 1;
//}

int X509AC_add_extension(X509AC *a, X509_EXTENSION *ex, int loc)
{
	X509_EXTENSION *new_ex=NULL;
	int n;
	STACK_OF(X509_EXTENSION) *sk=NULL;

	if((a == NULL)||(ex == NULL))
		return(0);

	if (&(a->info->extensions) == NULL)
	{
		X509err(X509_F_X509V3_ADD_EXT,ERR_R_PASSED_NULL_PARAMETER);
		goto err2;
	}

	if ((a->info->extensions) == NULL)
	{
		if ((sk=sk_X509_EXTENSION_new_null()) == NULL)
			goto err;
	}
	else
		sk= (a->info->extensions);

	n=sk_X509_EXTENSION_num(sk);
	if (loc > n) loc=n;
	else if (loc < 0) loc=n;

	if ((new_ex=X509_EXTENSION_dup(ex)) == NULL)
		goto err2;
	new_ex->object = OBJ_nid2obj(ex->object->nid);
	if (!sk_X509_EXTENSION_insert(sk,new_ex,loc))
		goto err;
	if ((a->info->extensions) == NULL)
		(a->info->extensions)=sk;
	return(1);
	err:
	X509err(X509_F_X509V3_ADD_EXT,ERR_R_MALLOC_FAILURE);
	err2:
	if (new_ex != NULL) X509_EXTENSION_free(new_ex);
	if (sk != NULL) sk_X509_EXTENSION_free(sk);
	return 0;
}

