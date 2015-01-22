/*
 * AttributeCertificateResp.cpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateResp.hpp"
#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/x509acresp.h"

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_PEM(AttributeCertificateRespAsn1, X509AC_RESP)


AttributeCertificateResp::AttributeCertificateResp(const std::vector<cryptobase::AttributeCertificate>& acs) :
	AttributeCertificateRespAsn1(X509AC_RESP_new())
{
	internal_->attrCert = sk_X509AC_new_null();
	for(auto ac : acs)
		sk_X509AC_push(internal_->attrCert, X509AC_dup(ac.internal_));
	ASN1_INTEGER_set(internal_->statusInfo->status, ACStatusInfo::ACStatus::granted);
}
AttributeCertificateResp::AttributeCertificateResp(const AttributeCertificate& ac) :
		AttributeCertificateRespAsn1(X509AC_RESP_new())
{
	internal_->attrCert = sk_X509AC_new_null();
	sk_X509AC_push(internal_->attrCert, X509AC_dup(ac.internal_));
//	internal_->attrCert = X509AC_dup(ac.internal_);
	ASN1_INTEGER_set(internal_->statusInfo->status, ACStatusInfo::ACStatus::granted);
}

AttributeCertificateResp::AttributeCertificateResp(const std::string& rejectionText, ACStatusInfo::ACFailureInfo rejectionInfo) :
		AttributeCertificateRespAsn1(X509AC_RESP_new())
{
	internal_->statusInfo->status = ASN1_INTEGER_new();
	ASN1_INTEGER_set(internal_->statusInfo->status, ACStatusInfo::ACStatus::rejection);
	internal_->statusInfo->text = ASN1_UTF8STRING_new();
	ASN1_STRING_set(internal_->statusInfo->text, rejectionText.c_str(), rejectionText.length());
	internal_->statusInfo->failInfo = ASN1_INTEGER_new();
	ASN1_INTEGER_set(internal_->statusInfo->failInfo, rejectionInfo);

}

AttributeCertificateResp::AttributeCertificateResp(X509AC_RESP* p) :
		AttributeCertificateRespAsn1(p)
{
}

AttributeCertificateResp::AttributeCertificateResp(const ByteArray& derEncoded) :
		AttributeCertificateRespAsn1(derEncoded)
{
}

AttributeCertificateResp::AttributeCertificateResp(const std::string& pemEncoded) :
		AttributeCertificateRespAsn1(pemEncoded)
{
}

AttributeCertificateResp::~AttributeCertificateResp()
{
}

//std::unique_ptr<AttributeCertificate> AttributeCertificateResp::getAc() const
//{
//	std::unique_ptr<AttributeCertificate> ac;
//	if(internal_->attrCert != nullptr)
//		ac.reset(new AttributeCertificate(X509AC_dup(sk_X509AC_value(internal_->attrCert, 0))));
//	return ac;
//}

std::vector<AttributeCertificate> AttributeCertificateResp::getAcs() const
{
	std::vector<AttributeCertificate> acs;
	int count = sk_X509AC_num(internal_->attrCert);
	acs.reserve(count);
	for(int i = 0; i < count; i++)
	{
		acs.push_back(AttributeCertificate(X509AC_dup(sk_X509AC_value(internal_->attrCert, i))));
	}
	return acs;
}

ACStatusInfo AttributeCertificateResp::getStatusInfo() const
{
	return ACStatusInfo(X509AC_STATUS_INFO_dup(internal_->statusInfo));
}

bool AttributeCertificateResp::granted() const
{
	return ASN1_INTEGER_get(internal_->statusInfo->status) == 0;
}

} /* namespace cryptobase */
