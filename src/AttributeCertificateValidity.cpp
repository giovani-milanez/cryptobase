/*
 * AttributeCertificateValidity.cpp
 *
 *  Created on: 17/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateValidity.hpp"
#include "cryptobase/x509ac.h"
#include "cryptobase/TimeFunctions.hpp"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS(AttributeCertificateValidityAsn1, X509AC_VAL)

AttributeCertificateValidity::AttributeCertificateValidity(X509AC_VAL *p) :
		AttributeCertificateValidityAsn1(p)
{
}

AttributeCertificateValidity::AttributeCertificateValidity(const GeneralizedTime& notBefore, const GeneralizedTime& notAfter) :
		AttributeCertificateValidityAsn1(X509AC_VAL_new())
{
	ASN1_GENERALIZEDTIME_free(internal_->notBefore);
	ASN1_GENERALIZEDTIME_free(internal_->notAfter);
	internal_->notBefore = ASN1_GENERALIZEDTIME_dup(notBefore.internal_);
	internal_->notAfter = ASN1_GENERALIZEDTIME_dup(notAfter.internal_);
}

AttributeCertificateValidity::AttributeCertificateValidity(std::uint32_t minutesValidity) :
		AttributeCertificateValidityAsn1(X509AC_VAL_new())
{
	timeval notBeforeTv, notAfterTv;
	gettimeofday(&notBeforeTv, nullptr);
	notAfterTv.tv_sec = notBeforeTv.tv_sec + (minutesValidity * 60);
	notAfterTv.tv_usec = notBeforeTv.tv_usec;

	GeneralizedTime notBefore(notBeforeTv);
	GeneralizedTime notAfter(notAfterTv);

	ASN1_GENERALIZEDTIME_free(internal_->notBefore);
	ASN1_GENERALIZEDTIME_free(internal_->notAfter);
	internal_->notBefore = ASN1_GENERALIZEDTIME_dup(notBefore.internal_);
	internal_->notAfter = ASN1_GENERALIZEDTIME_dup(notAfter.internal_);
}

AttributeCertificateValidity::~AttributeCertificateValidity()
{
}

GeneralizedTime AttributeCertificateValidity::getNotAfter() const
{
	return GeneralizedTime(ASN1_GENERALIZEDTIME_dup(internal_->notAfter));
}

GeneralizedTime AttributeCertificateValidity::getNotBefore() const
{
	return GeneralizedTime(ASN1_GENERALIZEDTIME_dup(internal_->notBefore));
}

} /* namespace cryptobase */
