/*
 * ObjectDigestInfo.hpp
 *
 *  Created on: 11/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef OBJECTDIGESTINFO_HPP_
#define OBJECTDIGESTINFO_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ObjectIdentifier.hpp"

typedef struct X509AC_OBJECT_DIGESTINFO_st X509AC_OBJECT_DIGESTINFO;

namespace cryptobase {

ASN1_DECLARE_CLASS(ObjectDigestInfoAsn1, X509AC_OBJECT_DIGESTINFO)

class CRYPTOBASE_API ObjectDigestInfo : public ObjectDigestInfoAsn1
{
public:
	enum ObjectType {
        publicKey = 0,
        publicKeyCert = 1,
        otherObjectTypes = 2
	};

	ObjectDigestInfo(X509AC_OBJECT_DIGESTINFO *p);
	virtual ~ObjectDigestInfo();

	ObjectType getDigestedObjectType() const;
	ObjectIdentifier getDigestAlgorithm() const;
	ByteArray getObjectDigest() const;

	bool operator ==(const ObjectDigestInfo& value) const;
	bool operator !=(const ObjectDigestInfo& value) const;
};

} /* namespace cryptobase */
#endif /* OBJECTDIGESTINFO_HPP_ */
