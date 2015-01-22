/*
 * Certificate.cpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 08/10/2013
 */

#include "cryptobase/Certificate.hpp"
#include "cryptobase/GeneralizedTime.hpp"
#include "cryptobase/MessageDigest.hpp"

#include <openssl/x509.h>

namespace cryptobase {

ASN1_IMPLEMENT_CLASS_PEM(CertificateAsn1, X509)

Certificate::Certificate(X509* p) :
		CertificateAsn1(p)
{
}

Certificate::Certificate(const ByteArray& derEncoded) :
		CertificateAsn1(derEncoded)
{
}

Certificate::Certificate(const std::string& pemEncoded) :
		CertificateAsn1(pemEncoded)
{
}

Certificate::~Certificate()
{
}

unsigned long Certificate::getSerialNumber() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(internal_), nullptr);
	unsigned long tmp = BN_get_word(bn);
	BN_free(bn);
	return tmp;
}

std::string Certificate::getSerialNumberString() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(internal_), nullptr);
	char *str = BN_bn2dec(bn);
	std::string ret(str);
	OPENSSL_free(str);
	BN_free(bn);
	return ret;
}

ObjectIdentifier Certificate::getSignatureAlgorithm() const
{
	return ObjectIdentifier(OBJ_dup(internal_->sig_alg->algorithm));
}

PublicKey Certificate::getPublicKey() const
{
	return PublicKey(X509_get_pubkey(internal_));
}

long Certificate::getVersion() const
{
	return X509_get_version(internal_);
}

timeval Certificate::getNotBefore() const
{
	return GeneralizedTime::asn1TimeToTv(X509_get_notBefore(internal_));
}

timeval Certificate::getNotAfter() const
{
	return GeneralizedTime::asn1TimeToTv(X509_get_notAfter(internal_));
}

X509Name Certificate::getIssuer() const
{
	return X509Name(X509_NAME_dup(internal_->cert_info->issuer));
}

X509Name Certificate::getSubject() const
{
	return X509Name(X509_NAME_dup(internal_->cert_info->subject));
}

std::vector<Extension> Certificate::getExtensions() const
{
	int count = sk_X509_EXTENSION_num(internal_->cert_info->extensions);
	std::vector<Extension> exts;
	exts.reserve(count);
	for(int i = 0; i < count; i++)
		exts.push_back(Extension(X509_EXTENSION_dup(sk_X509_EXTENSION_value(internal_->cert_info->extensions, i))));

	return exts;
}

ByteArray Certificate::getFingerPrint(DigestAlg algorithm) const
{
	ByteArray der = getDerEncoded();
	MessageDigest md(algorithm);
	return md.doFinal(der);
}

bool Certificate::operator ==(const Certificate& value)
{
	return X509_cmp(internal_, value.internal_) == 0;
}

bool Certificate::operator !=(const Certificate& value)
{
	return !this->operator==(value);
}

Certificate Certificate::fromFile(const std::string& filePath)
{
	ByteArray certBa = createFromFile(filePath);

	try
	{
		return Certificate(certBa); // try instantiate DER certificate
	}
	catch(const DerDecodeException& ex)
	{
		// oops, lets try PEM
		try
		{
			return Certificate(std::string((const char *)certBa.begin(), certBa.size()));
		}
		catch(const PemDecodeException& ex)
		{
			// invalid certificate!
			throw EncodeException("Invalid certificate format! (Tried to read DER and PEM)");
		}
	}
}

} /* namespace cryptobase */
