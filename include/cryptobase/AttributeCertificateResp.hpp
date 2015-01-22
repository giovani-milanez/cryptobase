/*
 * AttributeCertificateReq.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTECERTIFICATERESP_HPP_
#define ATTRIBUTECERTIFICATERESP_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/ACStatusInfo.hpp"

#include <memory>
#include <vector>

typedef struct X509AC_RESP_st X509AC_RESP;

namespace cryptobase {

class AttributeCertificate;

ASN1_DECLARE_CLASS_PEM(AttributeCertificateRespAsn1, X509AC_RESP)

class CRYPTOBASE_API AttributeCertificateResp : public  AttributeCertificateRespAsn1
{
public:
	explicit AttributeCertificateResp(const std::vector<cryptobase::AttributeCertificate>& acs);
	explicit AttributeCertificateResp(const AttributeCertificate& ac);
	AttributeCertificateResp(const std::string& rejectionText, ACStatusInfo::ACFailureInfo rejectionInfo);
	explicit AttributeCertificateResp(X509AC_RESP* p);
	explicit AttributeCertificateResp(const ByteArray& derEncoded);
	explicit AttributeCertificateResp(const std::string& pemEncoded);
	virtual ~AttributeCertificateResp();

//	std::unique_ptr<AttributeCertificate> getAc() const;
	std::vector<AttributeCertificate> getAcs() const;
	ACStatusInfo getStatusInfo() const;
	bool granted() const;

};

} /* namespace cryptobase */

#endif /* ATTRIBUTECERTIFICATERESP_HPP_ */
