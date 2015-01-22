/*
 * AttributeCertificateReq.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATEREQ_HPP_
#define ATTRIBUTECERTIFICATEREQ_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/AttributeCertificateIssueInfo.hpp"

#include <memory>

typedef struct X509AC_REQ_st X509AC_REQ;

namespace cryptobase {

class Holder;
class Certificate;
class X509Name;
class AttributeCertificateValidity;
class Attribute;
class Extension;
class AttributeCertificateIssueInfo;
class AttributeCertificateSearchInfo;
class AttributeCertificateRevInfo;

ASN1_DECLARE_CLASS_PEM(AttributeCertificateReqAsn1, X509AC_REQ)

class CRYPTOBASE_API AttributeCertificateReq : public  AttributeCertificateReqAsn1
{
public:
	enum ReqType{
		ISSUE = 1,
		REVOKE = 2,
		SEARCH = 3
	};
	explicit AttributeCertificateReq(const cryptobase::AttributeCertificateIssueInfo& issueInfo);
	explicit AttributeCertificateReq(const cryptobase::AttributeCertificateSearchInfo& searchInfo);
	explicit AttributeCertificateReq(const cryptobase::AttributeCertificateRevInfo& revInfo);
	explicit AttributeCertificateReq(X509AC_REQ* p);
	explicit AttributeCertificateReq(const ByteArray& derEncoded);
	explicit AttributeCertificateReq(const std::string& pemEncoded);

	virtual ~AttributeCertificateReq();

	ReqType getReqType() const;
	int getVersion() const;
	std::unique_ptr<AttributeCertificateIssueInfo> getIssueInfo() const;
	std::unique_ptr<AttributeCertificateSearchInfo> getSearchInfo() const;
	std::unique_ptr<AttributeCertificateRevInfo> getRevInfo() const;
};

} /* namespace cryptobase */

#endif /* ATTRIBUTECERTIFICATEREQ_HPP_ */
