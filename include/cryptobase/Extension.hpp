/*
 * Extension.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 17/09/2013
 */

#ifndef EXTENSION_HPP_
#define EXTENSION_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ObjectIdentifier.hpp"

#include <vector>

typedef struct X509_extension_st X509_EXTENSION;

namespace cryptobase {

ASN1_DECLARE_CLASS(ExtensionAsn1, X509_EXTENSION)

class CRYPTOBASE_API Extension : public ExtensionAsn1
{
public:
	explicit Extension(X509_EXTENSION *p);
	Extension(const cryptobase::ObjectIdentifier oid, const std::string& value, bool critical);
	Extension(const cryptobase::ObjectIdentifier oid, bool critical);
	virtual ~Extension();

	bool isCritical() const;
	ObjectIdentifier getOid() const;
	ByteArray getValue() const;

	static Extension createDistPoint(const std::vector<std::string>& distPoints);
	static Extension createNoRevAvail();
};

} /* namespace cryptobase */
#endif /* EXTENSION_HPP_ */
