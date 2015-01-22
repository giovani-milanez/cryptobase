/*
 * Extension.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 17/09/2013
 */

#include "cryptobase/Extension.hpp"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(ExtensionAsn1, X509_EXTENSION)

Extension::Extension(X509_EXTENSION *p) :
	ExtensionAsn1(p)
{
}

Extension::Extension(const cryptobase::ObjectIdentifier oid, const std::string& value, bool critical) :
	ExtensionAsn1(X509_EXTENSION_new())
{
	internal_->object = OBJ_dup(oid.internal_);
	ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(oct, (const unsigned char *)value.c_str(), value.length());
	X509_EXTENSION_set_data(internal_, oct);	
	internal_->critical = critical;
}

Extension::Extension(const cryptobase::ObjectIdentifier oid, bool critical) :
	ExtensionAsn1(X509_EXTENSION_new())
{
	internal_->object = OBJ_dup(oid.internal_);
	internal_->critical = critical;
}

Extension::~Extension()
{
}

bool Extension::isCritical() const
{
	return internal_->critical;
}

ObjectIdentifier Extension::getOid() const
{
	return ObjectIdentifier(OBJ_dup(internal_->object));
}

ByteArray Extension::getValue() const
{
	return ByteArray((const unsigned char *)internal_->value->data, internal_->value->length);
}

Extension Extension::createDistPoint(const std::vector<std::string>& distPoints)
{
	STACK_OF(DIST_POINT) *crldp = sk_DIST_POINT_new_null();
	DIST_POINT *point = DIST_POINT_new();
	sk_DIST_POINT_push(crldp, point);

	GENERAL_NAMES *uris = GENERAL_NAMES_new();
	for(auto distPoint : distPoints)
	{
		GENERAL_NAME *uri = GENERAL_NAME_new();
		uri->type = GEN_URI;
		uri->d.ia5 = M_ASN1_IA5STRING_new();
		ASN1_STRING_set(uri->d.ia5, distPoint.c_str(), distPoint.length());
		sk_GENERAL_NAME_push(uris, uri);
	}
	point->distpoint = DIST_POINT_NAME_new();
	point->distpoint->name.fullname = uris;
	point->distpoint->type = 0;

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_crl_distribution_points, 0, crldp);
	Extension ext(ex);
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	return ext;
}

Extension Extension::createNoRevAvail()
{
	return Extension(cryptobase::ObjectIdentifier(NID_no_rev_avail), false);
}

} /* namespace cryptobase */
