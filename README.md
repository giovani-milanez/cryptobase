# cryptobase
A C++ library for dealing with attribute certificates and others structures

This library was built during my final paper, when I realized that there was no suitable alternatives
to manage X509 Attribute Certificate (RFC 5755) in C/C++.

The library allows you to work with other things like X509 Certificates, Certificate Revocation List and Asymmetric Keys,
but it is focused in implementing the ASN.1 structures defined in my final paper for a attribute certificate 
management protocol.

It uses and encapsulates OpenSSL structures in order to provide high level classes.

## Examples
Parsing a attribute certificate

```c++
#include "cryptobase/AttributeCertificate.hpp"

#include <iostream>

using namespace cryptobase;

int main()
{
	try
	{
		AttributeCertificate ac(createFromFile("/home/giovani/Certificado.der"));
		AttributeCertificateInfo info = ac.getInfo();

		std::cout << "Version: " << info.getVersion() << std::endl << std::endl;

		Holder holder = info.getHolder();
		std::cout << "HOLDER TYPE: ";
		if(holder.getType() == Holder::HolderType::BASE_CERT_ID)
		{
			std::cout << "BASE CERT ID" << std::endl;
			std::cout << "Issuer: " << holder.getHolderBaseCertId().getIssuer().getOneLine() << std::endl;
			std::cout << "Serial: " << holder.getHolderBaseCertId().getSerialString() << std::endl;
		}
		else if (holder.getType() == Holder::HolderType::ENTITY_NAME)
		{
			std::cout << "ENTITY NAME" << std::endl;
			std::cout << "Issuer: " << holder.getHolderEntityName().getOneLine() << std::endl;
		}
		else if (holder.getType() == Holder::HolderType::OBJECT_DIGEST_INFO)
		{
			std::cout << "OBJECT DIGEST INFO" << std::endl;
			std::cout << "Algorithm: " << holder.getHolderObjectDigestInfo().getDigestAlgorithm().getName() << std::endl;
			std::cout << "Digest: " << hex(holder.getHolderObjectDigestInfo().getObjectDigest()) << std::endl;
		}
		std::cout << std::endl;

		std::cout << "Issuer: " << info.getIssuer().getOneLine() << std::endl << std::endl;
		std::cout << "Signature: " << info.getSignature().getName() << std::endl << std::endl;
		std::cout << "Serial Number: " << info.getSerialString() << std::endl << std::endl;
		std::cout << "Validity(epoch): " << info.getValidity().getNotBefore().getEpoch() << " to "
				<< info.getValidity().getNotAfter().getEpoch() << std::endl << std::endl;

		for(auto& attribute : info.getAttributes())
		{
			std::cout << "Attribute: " << attribute.getOid().getOidStr() << " - ";
			for(auto& value : attribute.getValues())
				std::cout << value << " - ";
			std::cout << std::endl;
		}
		std::cout << std::endl;

		for(auto& extension : info.getExtensions())
		{
			std::cout << "Extension: " << extension.getOid().getOidStr() << " - " << extension.getValue() << std::endl;
		}
		std::cout << std::endl;

		std::cout << "Signature" << std::endl;
		std::cout << "Algorithm: " << ac.getSignatureAlgorithm().getName() << std::endl;
		std::cout << "Value: " << hex(ac.getSignature()) << std::endl;
	}
	catch(const cryptobase::Exception& ex)
	{
		std::cout << ex.displayText() << std::endl;
	}
}
```
Issuing a Attribute Certificate

```c++
#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/Certificate.hpp"
#include "cryptobase/PrivateKey.hpp"

#include <iostream>

using namespace cryptobase;

int main()
{
	OpenSSL_add_all_algorithms();
	try
	{
		ByteArray privKeyPemBa = createFromFile("/home/giovani/certificado/giovani/keys");
		ByteArray certPemBa = createFromFile("/home/giovani/certificado/giovani/cert");
		ByteArray holderPemBa = createFromFile("/home/giovani/certificado/cert_juliano.pem");

		PrivateKey privKey(std::string((const char *)privKeyPemBa.begin(), privKeyPemBa.size()), "123456");
		Certificate certIssuer(std::string((const char *)certPemBa.begin(), certPemBa.size()));
		Certificate certHolder(std::string((const char *)holderPemBa.begin(), holderPemBa.size()));

		std::uint64_t serial = 1;
		AttributeCertificate ac(privKey,
					DigestAlg::SHA512,
					Holder(certHolder),
					certIssuer.getSubject(),
					serial,
					AttributeCertificateValidity(30), // 30 minutes validity
					std::vector<Attribute>{ {ObjectIdentifier("1.2.3.4.5"), "administrator"} }
					);
		// save to disk
		std::ofstream fileAc("/home/giovani/certificado/giovani/ac");
		fileAc << ac.getDerEncoded();
	}
	catch(const cryptobase::Exception& ex)
	{
		std::cout << ex.displayText() << std::endl;
	}
}
```
## Building

CMake and OpenSSL development files is neeeded.

### Building on Linux
```
cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles"
cd build
make
sudo make install
```
