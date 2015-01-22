/*
 * ACStatusInfo.cpp
 *
 *  Created on: 21/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/ACStatusInfo.hpp"
#include "cryptobase/x509acresp.h"


namespace cryptobase {

ASN1_IMPLEMENT_CLASS(ACStatusInfoAsn1, X509AC_STATUS_INFO)

ACStatusInfo::ACStatusInfo(X509AC_STATUS_INFO *p) :
		ACStatusInfoAsn1(p)
{
}

ACStatusInfo::~ACStatusInfo()
{
}

ACStatusInfo::ACStatus ACStatusInfo::getStatus() const
{
	return (ACStatusInfo::ACStatus) ASN1_INTEGER_get(internal_->status);
}

ACStatusInfo::ACFailureInfo ACStatusInfo::getFailInfo() const
{
	return (ACStatusInfo::ACFailureInfo) ASN1_INTEGER_get(internal_->failInfo);
}

std::string ACStatusInfo::getText() const
{
	return std::string((char *)internal_->text->data, internal_->text->length);
}

} /* namespace cryptobase */
