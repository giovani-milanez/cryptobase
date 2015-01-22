/*
 * AttributeCertificateReq.cpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "cryptobase/AttributeCertificateReq.hpp"
#include "cryptobase/AttributeCertificateIssueInfo.hpp"
#include "cryptobase/AttributeCertificateSearchInfo.hpp"
#include "cryptobase/AttributeCertificateRevInfo.hpp"
#include "cryptobase/x509acreq.h"

#include <sstream>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_PEM(AttributeCertificateReqAsn1, X509AC_REQ)

AttributeCertificateReq::AttributeCertificateReq(const cryptobase::AttributeCertificateIssueInfo& issueInfo) :
		AttributeCertificateReqAsn1(X509AC_REQ_new())
{
	ASN1_INTEGER_set(internal_->version, 1);
	ASN1_INTEGER_set(internal_->reqType, ReqType::ISSUE);
	internal_->issueInfo = X509AC_ISSUE_INFO_dup(issueInfo.internal_);
}

AttributeCertificateReq::AttributeCertificateReq(const cryptobase::AttributeCertificateSearchInfo& searchInfo) :
		AttributeCertificateReqAsn1(X509AC_REQ_new())
{
	ASN1_INTEGER_set(internal_->version, 1);
	ASN1_INTEGER_set(internal_->reqType, ReqType::SEARCH);
	internal_->searchInfo = X509AC_SEARCH_INFO_dup(searchInfo.internal_);
}

AttributeCertificateReq::AttributeCertificateReq(const cryptobase::AttributeCertificateRevInfo& revInfo) :
		AttributeCertificateReqAsn1(X509AC_REQ_new())
{
	ASN1_INTEGER_set(internal_->version, 1);
	ASN1_INTEGER_set(internal_->reqType, ReqType::REVOKE);
	internal_->revInfo = X509AC_REV_INFO_dup(revInfo.internal_);
	/*ASN1_INTEGER_set(internal_->version, 1);
	ASN1_INTEGER_set(internal_->reqType, ReqType::REVOKE);

	std::stringstream ss;
	ss << revInfo;
	std::string serialStr = ss.str();
	BIGNUM *bn = BN_new();
	BN_dec2bn(&bn, serialStr.c_str());
	if(internal_->revInfo != nullptr)
		ASN1_INTEGER_free(internal_->revInfo);
	internal_->revInfo = BN_to_ASN1_INTEGER(bn, nullptr);
	BN_free(bn);*/
}

AttributeCertificateReq::AttributeCertificateReq(X509AC_REQ* p) :
		AttributeCertificateReqAsn1(p)
{
}

AttributeCertificateReq::AttributeCertificateReq(const ByteArray& derEncoded) :
		AttributeCertificateReqAsn1(derEncoded)
{
}

AttributeCertificateReq::AttributeCertificateReq(const std::string& pemEncoded) :
		AttributeCertificateReqAsn1(pemEncoded)
{
}

AttributeCertificateReq::~AttributeCertificateReq()
{
}

AttributeCertificateReq::ReqType AttributeCertificateReq::getReqType() const
{
	return (ReqType)ASN1_INTEGER_get(internal_->reqType);
}

int AttributeCertificateReq::getVersion() const
{
	return ASN1_INTEGER_get(internal_->version);
}

std::unique_ptr<AttributeCertificateIssueInfo> AttributeCertificateReq::getIssueInfo() const
{
	std::unique_ptr<AttributeCertificateIssueInfo> issueInfo(nullptr);
	if(internal_->issueInfo != nullptr)
		issueInfo.reset(new AttributeCertificateIssueInfo(X509AC_ISSUE_INFO_dup(internal_->issueInfo)));
	return issueInfo;
}

std::unique_ptr<AttributeCertificateSearchInfo> AttributeCertificateReq::getSearchInfo() const
{
	std::unique_ptr<AttributeCertificateSearchInfo> searchInfo(nullptr);
	if(internal_->searchInfo != nullptr)
		searchInfo.reset(new AttributeCertificateSearchInfo(X509AC_SEARCH_INFO_dup(internal_->searchInfo)));
	return searchInfo;
}

std::unique_ptr<AttributeCertificateRevInfo> AttributeCertificateReq::getRevInfo() const
{
	std::unique_ptr<AttributeCertificateRevInfo> revInfo(nullptr);
	if(internal_->revInfo != nullptr)
		revInfo.reset(new AttributeCertificateRevInfo(X509AC_REV_INFO_dup(internal_->revInfo)));
	return revInfo;
	//std::unique_ptr<std::string> revInfo(nullptr);
	//if(internal_->revInfo != nullptr)
	//{
	//	BIGNUM *bn = ASN1_INTEGER_to_BN(internal_->revInfo, nullptr);
	//	char *str = BN_bn2dec(bn);
	//	revInfo.reset(new std::string(str));
	//	OPENSSL_free(str);
	//	BN_free(bn);
	//}
	//return revInfo;
}

} /* namespace cryptobase */

