/*
 * X509Name.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 04/09/2013
 */

#include "cryptobase/X509Name.hpp"

#include <openssl/x509.h>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(X509NameAsn1, X509_NAME)

X509Name::X509Name(X509_NAME *p) :
	X509NameAsn1(p)
{
}

X509Name::X509Name(STACK_OF(X509_NAME_ENTRY) *entries) :
	X509NameAsn1(X509_NAME_new())
{
	if(entries == nullptr)
	{
		X509_NAME_free(internal_);
		throw NullPointerException("Null STACK_OF(X509_NAME_ENTRY) pointer.");
	}

	int num = sk_X509_NAME_ENTRY_num(entries);
	for (int i = 0; i < num; i++)
	{
		X509_NAME_ENTRY *nameEntry = sk_X509_NAME_ENTRY_pop(entries);
		X509_NAME_add_entry(internal_, nameEntry, -1, 0); // nameEntry is dupped inside
	}
	sk_X509_NAME_ENTRY_free(entries);
}

X509Name::~X509Name()
{
}

void X509Name::addEntry(EntryType type, const std::string& value)
{
	Entry oneEntry = std::make_pair(ObjectIdentifier(OBJ_nid2obj(type)), value);
	X509_NAME_add_entry_by_txt(internal_, oneEntry.first.getName().c_str(), MBSTRING_ASC, (const unsigned char *)value.c_str(), -1, -1, 0);
}

void X509Name::addEntry(const ObjectIdentifier& oid, const std::string& value)
{
	Entry oneEntry = std::make_pair(oid, value);
	X509_NAME_add_entry_by_OBJ(internal_, oneEntry.first.internal_, MBSTRING_ASC, (unsigned char *)value.c_str(), -1, -1, 0);
}

std::vector<std::string> X509Name::getEntries(EntryType type) const
{
	std::vector<std::string> ret;
	for (auto entry : getEntries())
		if (entry.first.getNid() == type)
			ret.push_back(entry.second);

	return ret;
}

std::string X509Name::getEntry(const ObjectIdentifier& oid) const
{
	for (auto entry : getEntries())
		if(entry.first == oid)
			return entry.second;

	return "";
}

std::vector<Entry> X509Name::getEntries() const
{
	std::vector<Entry> entries;
	int num = sk_X509_NAME_ENTRY_num(internal_->entries);
	for (int i = 0; i < num; i++)
	{
		X509_NAME_ENTRY *nameEntry = sk_X509_NAME_ENTRY_value(internal_->entries, i);
		Entry oneEntry =
				std::make_pair(ObjectIdentifier(OBJ_dup(nameEntry->object)), (const char*)ASN1_STRING_data(nameEntry->value));
		entries.push_back(oneEntry);
	}
	return entries;
}

std::string X509Name::getOneLine() const
{
	char buf[255];
	X509_NAME_oneline(internal_, buf, sizeof(buf));
	return std::string(buf);
}

bool X509Name::operator ==(const X509Name& value) const
{
	return X509_NAME_cmp(internal_, value.internal_) == 0;
}

bool X509Name::operator !=(const X509Name& value) const
{
	return !this->operator==(value);
}


} /* namespace cryptobase */
