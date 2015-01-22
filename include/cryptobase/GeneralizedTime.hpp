/*
 * GeneralizedTime.hpp
 *
 *  Created on: 07/08/2012
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef GENERALIZEDTIME_HPP_
#define GENERALIZEDTIME_HPP_

#include "cryptobase/Asn1Class.hpp"

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <winsock.h>
#else
#include <sys/time.h>
#endif

typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_TIME;
CRYPTOBASE_DECLARE_ASN1_DUP_FUNCTION(ASN1_GENERALIZEDTIME)

namespace cryptobase {

ASN1_DECLARE_CLASS(GeneralizedTimeAsn1, ASN1_GENERALIZEDTIME)

class CRYPTOBASE_API GeneralizedTime : public GeneralizedTimeAsn1
{
public:
	explicit GeneralizedTime(ASN1_GENERALIZEDTIME *generalized);
	explicit GeneralizedTime(timeval& time);
	explicit GeneralizedTime(time_t epoch);

	virtual ~GeneralizedTime();

	std::string getTime() const;
	std::string getUtcTime() const;
	timeval getTimeVal() const;
	time_t getEpoch() const;

	static timeval asn1TimeToTv(ASN1_TIME *tm);
	static GeneralizedTime createFromZulu(const std::string& zulu);
};


} // namespace cryptobase

#endif /* GENERALIZEDTIME_HPP_ */
