/*
 * Holder.hpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef HOLDER_HPP_
#define HOLDER_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/IssuerSerial.hpp"
#include "cryptobase/ObjectDigestInfo.hpp"
#include "cryptobase/X509Name.hpp"

typedef struct X509AC_HOLDER_st X509AC_HOLDER;

namespace cryptobase {

class Certificate;

ASN1_DECLARE_CLASS(HolderAsn1, X509AC_HOLDER)

class CRYPTOBASE_API Holder : public HolderAsn1
{
public:
	enum class HolderType {
		BASE_CERT_ID, ENTITY_NAME, OBJECT_DIGEST_INFO
	};

	explicit Holder(const Certificate& holderCert);
	explicit Holder(const X509Name& holderName);
	explicit Holder(const IssuerSerial& baseCertId);

	explicit Holder(X509AC_HOLDER *p);
	virtual ~Holder();

	IssuerSerial getHolderBaseCertId() const;
	X509Name getHolderEntityName() const;
	ObjectDigestInfo getHolderObjectDigestInfo() const;

	bool operator ==(const Holder& value) const;
	bool operator !=(const Holder& value) const;

	HolderType getType() const;
private:
	HolderType type_;
};

inline Holder::HolderType Holder::getType() const
{
	return type_;
}

} /* namespace cryptobase */

#endif /* HOLDER_HPP_ */
