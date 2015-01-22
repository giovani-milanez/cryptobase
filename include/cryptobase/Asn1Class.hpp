/*
 * Asn1Class.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 03/09/2013
 */

#ifndef ASN1CLASS_HPP_
#define ASN1CLASS_HPP_

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
	#include <cstdint>	
	#include <WinSock2.h>	
	#include <Windows.h>	
#endif

#include "cryptobase/Defs.h"
#include "cryptobase/ByteArray.hpp"

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

namespace cryptobase {

#define ASN1OBJECT_DECLARE(OPENSSL_STRUCT) Asn1Object<OPENSSL_STRUCT, d2i_##OPENSSL_STRUCT, i2d_##OPENSSL_STRUCT, OPENSSL_STRUCT##_free, OPENSSL_STRUCT##_dup>
#define PEMASN1OBJECT_DECLARE(OPENSSL_STRUCT) PemAsn1Object<OPENSSL_STRUCT, d2i_##OPENSSL_STRUCT, i2d_##OPENSSL_STRUCT, OPENSSL_STRUCT##_free, OPENSSL_STRUCT##_dup, PEM_read_bio_##OPENSSL_STRUCT, PEM_write_bio_##OPENSSL_STRUCT, OPENSSL_STRUCT##_new>

#define PEM_DEF_NULL
#define PEM_IMPL_NULL

#define PEM_DEF(CLASSNAME) \
		explicit CLASSNAME(const std::string& pemEncoded);	\
			std::string getPemEncoded() const;

#define PEM_IMPL(CLASSNAME, OPENSSL_STRUCT)	\
    CLASSNAME::CLASSNAME(const std::string& pemEncoded)	\
    {    \
        BIO *buffer = BIO_new(BIO_s_mem());                                                                    \
        if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())    \
        {                                                                                                    \
            BIO_free(buffer);                                                                                \
            throw cryptobase::BufferWriteException("Could not write PEM to buffer"); 						 \
        }                                                                                                    \
        internal_ = PEM_read_bio_##OPENSSL_STRUCT(buffer, nullptr, nullptr, nullptr);                        \
        if (internal_ == nullptr)                                                                            \
        {                                                                                                    \
            BIO_free(buffer);                                                                                \
            throw cryptobase::PemDecodeException("");														 \
        }                                                                                                    \
        BIO_free(buffer);    \
    }    \
    std::string CLASSNAME::getPemEncoded() const    \
    {    \
        const char *data;                                        \
        BIO *buffer = BIO_new(BIO_s_mem());                        \
        PEM_write_bio_##OPENSSL_STRUCT(buffer, internal_);        \
        std::size_t ndata = BIO_get_mem_data(buffer, &data);    \
        std::string ret(data, ndata);                            \
        BIO_free(buffer);        \
        return ret;    \
    }

#define ASN1_DECLARE_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM)	\
	class CRYPTOBASE_API CLASSNAME	\
	{	\
        public:	\
            explicit CLASSNAME(OPENSSL_STRUCT *p);	\
            CLASSNAME(const CLASSNAME& src);	\
            CLASSNAME& operator=(const CLASSNAME& rhs);	\
            CLASSNAME(CLASSNAME&& src);	\
            CLASSNAME& operator=(CLASSNAME&& rhs);	\
            explicit CLASSNAME(const cryptobase::ByteArray& derEncoded);	\
            PEM	\
            cryptobase::ByteArray getDerEncoded() const;	\
            virtual ~CLASSNAME();	\
            OPENSSL_STRUCT *internal_;	\
        protected:	\
    };

#define ASN1_IMPLEMENT_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM, DUP_FUNC, FREE_FUNC)    \
    CLASSNAME::CLASSNAME(OPENSSL_STRUCT *p)    : \
        internal_(p)	\
	{	\
		if(p == nullptr)	\
			throw cryptobase::NullPointerException(""); \
	}    \
    CLASSNAME::~CLASSNAME() \
    {    \
        FREE_FUNC(internal_);    \
    }    \
    CLASSNAME::CLASSNAME(const CLASSNAME& src) :    \
        internal_(DUP_FUNC(src.internal_))\
    {    \
    }    \
    CLASSNAME& CLASSNAME::operator=(const CLASSNAME& rhs)    \
    {\
        OPENSSL_STRUCT *tmp = DUP_FUNC(rhs.internal_);    \
        FREE_FUNC(internal_);    \
        internal_ = tmp;    \
        return *this;    \
    }\
    CLASSNAME::CLASSNAME(CLASSNAME&& src) :    \
        internal_(src.internal_)    \
    {    \
        src.internal_ = nullptr;    \
    }    \
    CLASSNAME& CLASSNAME::operator=(CLASSNAME&& rhs)    \
    {    \
        if (this == &rhs)    \
            return *this;    \
        FREE_FUNC(internal_);    \
        internal_ = rhs.internal_;    \
        rhs.internal_ = nullptr;    \
        return *this;    \
    }    \
    CLASSNAME::CLASSNAME(const cryptobase::ByteArray& derEncoded)    \
    {    \
        const unsigned char *tmp = derEncoded.begin();    \
        internal_ = d2i_##OPENSSL_STRUCT(nullptr, &tmp, derEncoded.size()); \
        if (internal_ == nullptr)                                                                            \
        {                                                                                                    \
        	throw cryptobase::DerDecodeException("");														 \
        }    \
    }    \
    cryptobase::ByteArray CLASSNAME::getDerEncoded() const    \
    {    \
        std::size_t size = i2d_##OPENSSL_STRUCT(internal_, nullptr);    \
        cryptobase::ByteArray result(size);                                    \
        unsigned char *derPtr = result.begin();        \
        unsigned char *tmp = derPtr;                            \
        i2d_##OPENSSL_STRUCT(internal_, &tmp);    \
        return result;    \
    }    \
    PEM

#define ASN1_DECLARE_CLASS(CLASSNAME, OPENSSL_STRUCT) ASN1_DECLARE_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM_DEF_NULL)
#define ASN1_IMPLEMENT_CLASS(CLASSNAME, OPENSSL_STRUCT) ASN1_IMPLEMENT_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM_IMPL_NULL, OPENSSL_STRUCT##_dup, OPENSSL_STRUCT##_free)

#define ASN1_DECLARE_CLASS_PEM(CLASSNAME, OPENSSL_STRUCT) ASN1_DECLARE_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM_DEF(CLASSNAME))
#define ASN1_IMPLEMENT_CLASS_PEM(CLASSNAME, OPENSSL_STRUCT) ASN1_IMPLEMENT_CLASS_1(CLASSNAME, OPENSSL_STRUCT, PEM_IMPL(CLASSNAME, OPENSSL_STRUCT), OPENSSL_STRUCT##_dup, OPENSSL_STRUCT##_free)

#define CRYPTOBASE_DECLARE_ASN1_DUP_FUNCTION(OPENSSL_STRUCT) 				\
		OPENSSL_STRUCT * OPENSSL_STRUCT##_dup(OPENSSL_STRUCT *x);

#define CRYPTOBASE_IMPLEMENT_ASN1_DUP_FUNCTION(OPENSSL_STRUCT) 				\
	OPENSSL_STRUCT * OPENSSL_STRUCT##_dup(OPENSSL_STRUCT *x) 				\
	{ 																		\
		OPENSSL_STRUCT *ptr = (OPENSSL_STRUCT *) ASN1_item_dup(ASN1_ITEM_rptr(OPENSSL_STRUCT), x);	\
		return ptr;															\
	}

}

#endif /* ASN1CLASS_HPP_ */
