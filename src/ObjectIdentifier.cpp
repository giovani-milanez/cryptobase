/*
 * ObjectIdentifier.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#include "cryptobase/ObjectIdentifier.hpp"

#include <openssl/objects.h>

#include <string>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_1(ObjectIdentifierAsn1, ASN1_OBJECT, PEM_DEF_NULL, OBJ_dup, ASN1_OBJECT_free)

CRYPTOBASE_IMPLEMENT_EXCEPTION(UnknownOidException, Exception, "Unknown OID")
CRYPTOBASE_IMPLEMENT_EXCEPTION(CreateOidException, Exception, "Could not create OID")

ObjectIdentifier::ObjectIdentifier(const std::string& oid) :
	ObjectIdentifierAsn1(OBJ_txt2obj(oid.c_str(), 1))
{
	if(!internal_)
		throw UnknownOidException("Invalid OID: "+oid);
}

ObjectIdentifier::ObjectIdentifier(int nid) :
	ObjectIdentifierAsn1(OBJ_nid2obj(nid))
{
	if(!internal_)
		throw UnknownOidException("Invalid NID: "+std::to_string(nid));
}

ObjectIdentifier::ObjectIdentifier(ASN1_OBJECT *p) :
	ObjectIdentifierAsn1(p)
{
}

ObjectIdentifier::~ObjectIdentifier()
{
}

std::string ObjectIdentifier::getOidStr() const
{
	char data[30];
	OBJ_obj2txt(data, 30, internal_, 1);
	return std::string(data);
}

int ObjectIdentifier::getNid() const
{
	return OBJ_obj2nid(internal_);
}

std::string ObjectIdentifier::getName() const
{
	return std::string(OBJ_nid2sn(getNid()));
}

std::string ObjectIdentifier::getLongName() const
{
	return std::string(OBJ_nid2ln(getNid()));
}

ObjectIdentifier ObjectIdentifier::createOid(const std::string& oid, const std::string& longName, const std::string& shortName)
{
	int nid = OBJ_create(oid.c_str(), shortName.c_str(), longName.c_str());

	if (nid == NID_undef)
	{
		throw CreateOidException("Could not create OID: NID_undef");
	}
	ASN1_OBJECT *asn1Obj = OBJ_nid2obj(nid);
	if (!asn1Obj)
	{
		throw CreateOidException("");
	}
	return ObjectIdentifier(asn1Obj);
}

bool ObjectIdentifier::operator ==(const ObjectIdentifier& value) const
{
	return getOidStr() == value.getOidStr();
}

bool ObjectIdentifier::operator !=(const ObjectIdentifier& value) const
{
	return !operator==(value);
}

} /* namespace cryptobase */
