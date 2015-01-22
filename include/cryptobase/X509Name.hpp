/*
 * X509Name.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#ifndef X509NAME_HPP_
#define X509NAME_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ObjectIdentifier.hpp"

#include <vector>

typedef struct X509_name_st X509_NAME;
struct stack_st_X509_NAME_ENTRY;

namespace cryptobase {

ASN1_DECLARE_CLASS(X509NameAsn1, X509_NAME)

typedef std::pair<ObjectIdentifier, std::string> Entry;

class CRYPTOBASE_API X509Name : public X509NameAsn1
{
public:
	enum EntryType
	{
		COUNTRY = 14,
		STATE_OR_PROVINCE = 16,
		LOCALITY = 15,
		ORGANIZATION = 17,
		ORGANIZATION_UNIT = 18,
		COMMON_NAME = 13,
		EMAIL = 48,
		DN_QUALIFIER = 174,
		SERIAL_NUMBER = 105,
		TITLE = 106,
		SURNAME = 100,
		GIVEN_NAME = 99,
		INITIALS = 101,
		PSEUDONYM = 510,
		GENERATION_QUALIFIER = 509,
		DOMAIN_COMPONENT = 391
	};

	explicit X509Name(X509_NAME *p);
	explicit X509Name(stack_st_X509_NAME_ENTRY *entries);
	virtual ~X509Name();

	void addEntry(EntryType type, const std::string& value);
	void addEntry(const ObjectIdentifier& oid, const std::string& value);
	std::vector<std::string> getEntries(EntryType type) const;
	std::string getEntry(const ObjectIdentifier& oid) const;

	std::vector<Entry> getEntries() const;
	std::string getOneLine() const;

	bool operator ==(const X509Name& value) const;
	bool operator !=(const X509Name& value) const;
};

} /* namespace cryptobase */
#endif /* X509NAME_HPP_ */
