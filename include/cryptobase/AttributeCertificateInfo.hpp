/*
 * AttributeCertificateInfo.hpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATEINFO_HPP_
#define ATTRIBUTECERTIFICATEINFO_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/Holder.hpp"
#include "cryptobase/X509Name.hpp"
#include "cryptobase/GeneralizedTime.hpp"
#include "cryptobase/Attribute.hpp"
#include "cryptobase/Extension.hpp"
#include "cryptobase/AttributeCertificateValidity.hpp"

typedef struct X509AC_INFO_st X509AC_INFO;

namespace cryptobase {

ASN1_DECLARE_CLASS(AttributeCertificateInfoAsn1, X509AC_INFO)

class CRYPTOBASE_API AttributeCertificateInfo : public AttributeCertificateInfoAsn1
{
public:
	AttributeCertificateInfo(X509AC_INFO *p);
	virtual ~AttributeCertificateInfo();

	int getVersion() const;
	Holder getHolder() const;
	X509Name getIssuer() const;
	ObjectIdentifier getSignature() const;

	/**
	 * Warning: may loose precision.
	 * Use getSerialString to correct value
	 */
	long int getSerial() const;
	std::string getSerialString() const;
	AttributeCertificateValidity getValidity() const;
	std::vector<Attribute> getAttributes() const;
	std::vector<Extension> getExtensions() const;
};

} /* namespace cryptobase */

#endif /* ATTRIBUTECERTIFICATEINFO_HPP_ */
