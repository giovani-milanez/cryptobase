/*
 * ObjectIdentifier.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#ifndef OBJECTIDENTIFIER_HPP_
#define OBJECTIDENTIFIER_HPP_

#include "cryptobase/Asn1Class.hpp"

#include <typeinfo>

typedef struct asn1_object_st ASN1_OBJECT;

namespace cryptobase {

ASN1_DECLARE_CLASS(ObjectIdentifierAsn1, ASN1_OBJECT)

CRYPTOBASE_DECLARE_EXCEPTION(CRYPTOBASE_API, UnknownOidException, Exception)
CRYPTOBASE_DECLARE_EXCEPTION(CRYPTOBASE_API, CreateOidException, Exception)

class CRYPTOBASE_API ObjectIdentifier : public ObjectIdentifierAsn1
{
public:
	explicit ObjectIdentifier(const std::string& oid);
	explicit ObjectIdentifier(int nid);
	explicit ObjectIdentifier(ASN1_OBJECT *p);
	virtual ~ObjectIdentifier();

	std::string getOidStr() const;
	int getNid() const;
	std::string getName() const;
	std::string getLongName() const;

	bool operator ==(const ObjectIdentifier& value) const;
	bool operator !=(const ObjectIdentifier& value) const;

	static ObjectIdentifier createOid(const std::string& oid, const std::string& longName, const std::string& shortName);
};

} /* namespace cryptobase */
#endif /* OBJECTIDENTIFIER_HPP_ */
