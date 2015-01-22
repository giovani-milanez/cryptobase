/*
 * Attribute.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 15/09/2013
 */

#include "cryptobase/Attribute.hpp"

#include <openssl/x509.h>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeAsn1, X509_ATTRIBUTE)

Attribute::Attribute(X509_ATTRIBUTE *p) :
	AttributeAsn1(p)
{
}

Attribute::Attribute(const ObjectIdentifier& oid, const std::string& value) :
		AttributeAsn1(X509_ATTRIBUTE_new())
{
	X509_ATTRIBUTE_set1_object(internal_, oid.internal_);
	X509_ATTRIBUTE_set1_data(internal_, V_ASN1_UTF8STRING, value.c_str(), value.length());
}

Attribute::Attribute(const ObjectIdentifier& oid, const ByteArray& value) :
		AttributeAsn1(X509_ATTRIBUTE_new())
{
	X509_ATTRIBUTE_set1_object(internal_, oid.internal_);
	X509_ATTRIBUTE_set1_data(internal_, V_ASN1_SEQUENCE, value.begin(), value.size());
}

Attribute::Attribute(const ObjectIdentifier& oid, const std::vector<std::string>& values) :
		AttributeAsn1(X509_ATTRIBUTE_new())
{
	X509_ATTRIBUTE_set1_object(internal_, oid.internal_);
	for(auto v : values)
		X509_ATTRIBUTE_set1_data(internal_, V_ASN1_UTF8STRING, v.c_str(), v.length());
}

Attribute::Attribute(const ObjectIdentifier& oid, const std::vector<ByteArray>& values) :
		AttributeAsn1(X509_ATTRIBUTE_new())
{
	X509_ATTRIBUTE_set1_object(internal_, oid.internal_);
	for(auto v : values)
		X509_ATTRIBUTE_set1_data(internal_, V_ASN1_SEQUENCE, v.begin(), v.size());
}

Attribute::~Attribute()
{
}

ObjectIdentifier Attribute::getOid() const
{
	return ObjectIdentifier(OBJ_dup(internal_->object));
}

std::vector<ByteArray> Attribute::getValues() const
{
	auto getValue = [] (const ASN1_TYPE *value)
	{
		switch(value->type)
		{
			case V_ASN1_OBJECT:
				return ObjectIdentifier(OBJ_dup(value->value.object)).getDerEncoded();
			default:
				return ByteArray((const unsigned char *)value->value.visiblestring->data, value->value.visiblestring->length);
		}
	};
	std::vector<ByteArray> values;

	if(internal_->single)
		values.push_back( getValue(internal_->value.single) );
	else
	{
		int count = sk_ASN1_TYPE_num(internal_->value.set);
		values.reserve(count);
		for(int i = 0; i < count; i++)
			values.push_back( getValue(sk_ASN1_TYPE_value(internal_->value.set, i)) );
	}
	return values;
}

} /* namespace cryptobase */
