/*
 * AttributeCertificateRevInfo.hpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef AttributeCertificateRevInfo_HPP_
#define AttributeCertificateRevInfo_HPP_

#include "cryptobase/Asn1Class.hpp"
#include "cryptobase/Holder.hpp"

#include <vector>
#include <memory>

typedef struct X509AC_REV_INFO_st X509AC_REV_INFO;

namespace cryptobase {

class ObjectIdentifier;

ASN1_DECLARE_CLASS(AttributeCertificateRevInfoAsn1, X509AC_REV_INFO)

class CRYPTOBASE_API AttributeCertificateRevInfo : public AttributeCertificateRevInfoAsn1
{
public:
	explicit AttributeCertificateRevInfo(const Holder& holder, const ObjectIdentifier& attrOid);
	explicit AttributeCertificateRevInfo(X509AC_REV_INFO *p);
	virtual ~AttributeCertificateRevInfo();

	void setAttributeOid(const ObjectIdentifier& attrOid);
	void setHolder(const Holder& holder);

	Holder getHolder() const;
	ObjectIdentifier getAttributeOid() const;
};

} /* namespace cryptobase */

#endif /* AttributeCertificateRevInfo_HPP_ */
