/*
 * GeneralizedTime.cpp
 *
 *  Created on: 07/08/2012
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "cryptobase/GeneralizedTime.hpp"
#include "cryptobase/TimeFunctions.hpp"

#include <openssl/ts.h>

#include <string>
#include <sstream>

CRYPTOBASE_IMPLEMENT_ASN1_DUP_FUNCTION(ASN1_GENERALIZEDTIME)

namespace cryptobase {


ASN1_IMPLEMENT_CLASS(GeneralizedTimeAsn1, ASN1_GENERALIZEDTIME)

GeneralizedTime::GeneralizedTime(timeval& time) :
		GeneralizedTimeAsn1(ASN1_GENERALIZEDTIME_new())
{

	char genTimeString[17 + TS_MAX_CLOCK_PRECISION_DIGITS];
	time_t secs = time.tv_sec;
	struct tm *tm = gmtime(&secs);

	int millis = time.tv_usec*0.001;
	if (millis == 0) {
		sprintf(genTimeString, "%04d%02d%02d%02d%02d%02dZ",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
				tm->tm_min, tm->tm_sec);
	}
	else {
		std::stringstream ss;
		ss << millis;
		std::string afterDot = ss.str();
		afterDot.insert(afterDot.begin(), 3-afterDot.size(), '0');
		afterDot.erase( afterDot.find_last_not_of('0') + 1); // REMOVE TRAILING ZERO

		#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
		_snprintf(genTimeString, 20,
				"%04d%02d%02d%02d%02d%02d.%sZ", tm->tm_year + 1900, tm->tm_mon + 1,
				tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, afterDot.c_str());
		#else
		snprintf(genTimeString, 20,
				"%04d%02d%02d%02d%02d%02d.%sZ", tm->tm_year + 1900, tm->tm_mon + 1,
				tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, afterDot.c_str());
		#endif


	}
	ASN1_GENERALIZEDTIME_set_string(internal_, genTimeString);
}

GeneralizedTime::GeneralizedTime(time_t epoch) :
	GeneralizedTimeAsn1(ASN1_GENERALIZEDTIME_new())
{
	ASN1_GENERALIZEDTIME_set(internal_, epoch);
}

GeneralizedTime::GeneralizedTime(ASN1_GENERALIZEDTIME* generalized) :
		GeneralizedTimeAsn1(generalized)
{
}


GeneralizedTime GeneralizedTime::createFromZulu(const std::string& zulu)
{
	ASN1_GENERALIZEDTIME *genTime = ASN1_GENERALIZEDTIME_new();
	ASN1_GENERALIZEDTIME_set_string(genTime, zulu.c_str());
	return GeneralizedTime(genTime);
}

GeneralizedTime::~GeneralizedTime()
{
}

std::string GeneralizedTime::getTime() const
{
	return std::string((const char*)internal_->data, internal_->length);
}

std::string GeneralizedTime::getUtcTime() const
{
	return getTime().substr(2,12) + "Z";
}

timeval GeneralizedTime::getTimeVal() const
{
	return GeneralizedTime::asn1TimeToTv(internal_);
}

time_t GeneralizedTime::getEpoch() const
{
	return getTimeVal().tv_sec;
}

timeval GeneralizedTime::asn1TimeToTv(ASN1_TIME *asn1Time)
{
	struct tm	rtm;
	time_t		rt;

	memset(&rtm, 0, sizeof(struct tm));

	/* convert ASN1 time string to struct tm structure elements	*/

	timeval tv;tv.tv_sec = 0; tv.tv_usec = 0;
	int i = 0;
	if(asn1Time == nullptr)
		return tv;
	if(asn1Time->type == V_ASN1_GENERALIZEDTIME)
		i = 2;
	if(asn1Time->data)
	{
		std::string data((const char*)asn1Time->data, asn1Time->length);

		rtm.tm_sec = atoi(data.substr(10+i, 2).c_str());
		rtm.tm_min = atoi(data.substr(8+i, 2).c_str());
		rtm.tm_hour = atoi(data.substr(6+i, 2).c_str());
		rtm.tm_mday = atoi(data.substr(4+i, 2).c_str());
		rtm.tm_mon = atoi(data.substr(2+i, 2).c_str()) - 1;
		rtm.tm_year = atoi(data.substr(0, 2+i).c_str());
		if (rtm.tm_year < 70)
			rtm.tm_year += 100;
		if(rtm.tm_year >= 1900)
			rtm.tm_year -= 1900;
		//rtm.tm_zone = 0;

		rt = timegm(&rtm);
		tv.tv_sec = rt;

		// calculate milliseconds
		if(asn1Time->type == V_ASN1_GENERALIZEDTIME)
		{
			unsigned pos = data.find(".");
			if(pos != std::string::npos)
			{
				std::string millis = data.substr(pos+1);
				millis = millis.substr(0, millis.size()-1);
				//int m = stoi(millis);
				std::istringstream ss(millis);
				int m;
				ss >> m;
				tv.tv_usec = m * 1000.0;
			}
		}
	}
	return tv;
}

} // namespace cryptobase
