/*
 * IssuerSerial.hpp
 *
 *  Created on: 11/09/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ISSUERSERIAL_HPP_
#define ISSUERSERIAL_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/X509Name.hpp"

typedef struct X509AC_ISSUER_SERIAL_st X509AC_ISSUER_SERIAL;

namespace cryptobase {

ASN1_DECLARE_CLASS(IssuerSerialAsn1, X509AC_ISSUER_SERIAL)

class CRYPTOBASE_API IssuerSerial : public IssuerSerialAsn1
{
public:
	explicit IssuerSerial(X509AC_ISSUER_SERIAL *p);
	IssuerSerial(const X509Name& issuer, const std::string& serial);
	virtual ~IssuerSerial();

	X509Name getIssuer() const;
	/**
	 * Warning, may loose precision.
	 */
	long int getSerial() const;
	std::string getSerialString() const;
	ByteArray getIssuerUid() const;

	bool operator ==(const IssuerSerial& value) const;
	bool operator !=(const IssuerSerial& value) const;
};

} /* namespace cryptobase */
#endif /* ISSUERSERIAL_HPP_ */
