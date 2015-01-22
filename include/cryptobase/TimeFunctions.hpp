/*
 * TimeFunctions.hpp
 *
 *      Author: Giovani Milanez Espindola
 *	   Contact: giovani.milanez@gmail.com
 *	Created on: 03/09/2013
 */

#ifndef CRYOTOBASE_TIMEFUNCTIONS_HPP_
#define CRYOTOBASE_TIMEFUNCTIONS_HPP_

#include "cryptobase/Defs.h"
#include <time.h>	

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)			
	#include <cstdint>	
/* FILETIME of Jan 1 1970 00:00:00. */
static const unsigned __int64 epoch = (std::uint64_t)116444736000000000ULL;

CRYPTOBASE_API int gettimeofday(struct timeval * tp, struct timezone * tzp);
#endif

#if defined(ANDROID_BUILD) || defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
CRYPTOBASE_API int is_leap(unsigned y);
CRYPTOBASE_API time_t timegm(struct tm *tm);
#endif

#endif
