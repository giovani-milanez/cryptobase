/*
 * AttributeCertificateValidity.hpp
 *
 *  Created on: 17/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATEVALIDITY_HPP_
#define ATTRIBUTECERTIFICATEVALIDITY_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/GeneralizedTime.hpp"

typedef struct X509AC_VAL_st X509AC_VAL;

namespace cryptobase {

ASN1_DECLARE_CLASS(AttributeCertificateValidityAsn1, X509AC_VAL)

class CRYPTOBASE_API AttributeCertificateValidity : public AttributeCertificateValidityAsn1
{
public:
	AttributeCertificateValidity(X509AC_VAL *p);
	AttributeCertificateValidity(const GeneralizedTime& notBefore, const GeneralizedTime& notAfter);
	/**
	 * notBefore will be the current system time
	 * notAfter will be notBefore + minutesValidity
	 */
	AttributeCertificateValidity(std::uint32_t minutesValidity);
	virtual ~AttributeCertificateValidity();

	GeneralizedTime getNotAfter() const;
	GeneralizedTime getNotBefore() const;

};

} /* namespace cryptobase */
#endif /* ATTRIBUTECERTIFICATEVALIDITY_HPP_ */
