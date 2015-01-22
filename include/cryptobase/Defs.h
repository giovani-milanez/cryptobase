#ifndef CRYPTOBASE_DEFS_
#define CRYPTOBASE_DEFS_

#ifdef _WIN32
#  ifdef cryptobase_EXPORTS
#    define CRYPTOBASE_API __declspec(dllexport)
#    define EXPIMP_TEMPLATE
#  else
#    define CRYPTOBASE_API __declspec(dllimport)
#    define EXPIMP_TEMPLATE extern
#  endif
#else
#  define CRYPTOBASE_API
#endif

#endif