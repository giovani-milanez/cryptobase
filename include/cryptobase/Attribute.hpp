/*
 * Attribute.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 15/09/2013
 */

#ifndef ATTRIBUTE_HPP_
#define ATTRIBUTE_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ObjectIdentifier.hpp"

#include <vector>

typedef struct x509_attributes_st X509_ATTRIBUTE;

namespace cryptobase {

ASN1_DECLARE_CLASS(AttributeAsn1, X509_ATTRIBUTE)

class CRYPTOBASE_API Attribute : public AttributeAsn1
{
public:
	Attribute(X509_ATTRIBUTE *p);
	Attribute(const ObjectIdentifier& oid, const std::string& value);
	Attribute(const ObjectIdentifier& oid, const ByteArray& value);
	Attribute(const ObjectIdentifier& oid, const std::vector<std::string>& values);
	Attribute(const ObjectIdentifier& oid, const std::vector<ByteArray>& values);
	virtual ~Attribute();

	ObjectIdentifier getOid() const;
	std::vector<ByteArray> getValues() const;

};

} /* namespace cryptobase */
#endif /* ATTRIBUTE_HPP_ */
