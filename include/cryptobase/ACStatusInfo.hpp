/*
 * ACStatusInfo.hpp
 *
 *  Created on: 21/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ACSTATUSINFO_HPP_
#define ACSTATUSINFO_HPP_

#include "cryptobase/Asn1Class.hpp"

typedef struct X509AC_STATUS_INFO_st X509AC_STATUS_INFO;

namespace cryptobase {

ASN1_DECLARE_CLASS(ACStatusInfoAsn1, X509AC_STATUS_INFO)

class CRYPTOBASE_API ACStatusInfo : public ACStatusInfoAsn1
{
public:

	enum ACStatus {
		granted = 0,
		rejection = 1
	};

	enum ACFailureInfo {
		badAlg = 0,
		badRequest = 2,
		badDataFormat = 5,
		integrityFail = 14,
		notApproved = 15,
		unacceptedExtension = 16,
		untrustedRequester = 17,
		untrustedHolder = 18,
		unsupportedAttribute = 19,
		unsupportedTemplate = 20,
		unknownSerial = 21,
		systemFailure = 25
	};

	ACStatusInfo(X509AC_STATUS_INFO *p);
	virtual ~ACStatusInfo();

	ACStatus getStatus() const;
	ACFailureInfo getFailInfo() const;
	std::string getText() const;

};

} /* namespace cryptobase */
#endif /* ACSTATUSINFO_HPP_ */
