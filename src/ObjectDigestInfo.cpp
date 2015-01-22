/*
 * ObjectDigestInfo.cpp
 *
 *  Created on: 11/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/ObjectDigestInfo.hpp"
#include "cryptobase/x509ac.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(ObjectDigestInfoAsn1, X509AC_OBJECT_DIGESTINFO)

ObjectDigestInfo::ObjectDigestInfo(X509AC_OBJECT_DIGESTINFO *p) :
		ObjectDigestInfoAsn1(p)
{
}

ObjectDigestInfo::~ObjectDigestInfo()
{
}

ObjectDigestInfo::ObjectType ObjectDigestInfo::getDigestedObjectType() const
{
	return (ObjectDigestInfo::ObjectType) ASN1_ENUMERATED_get(internal_->type);
}

ObjectIdentifier ObjectDigestInfo::getDigestAlgorithm() const
{
	return ObjectIdentifier(OBJ_dup(internal_->algor->algorithm));
}

ByteArray ObjectDigestInfo::getObjectDigest() const
{
	return ByteArray((const unsigned char *)internal_->digest->data, internal_->digest->length);
}


bool ObjectDigestInfo::operator ==(const ObjectDigestInfo& value) const
{
	return getObjectDigest() == value.getObjectDigest();
}

bool ObjectDigestInfo::operator !=(const ObjectDigestInfo& value) const
{
	return !this->operator==(value);
}

} /* namespace cryptobase */
