#define USE_STANDARD_FILE_FUNCTIONS
#include <ida.hpp>
#include <fpro.h>

#include "debmod.h"

#ifdef USE_ASYNC
//lint -esym(766,fpro.h) not used in module
AS_PRINTF(1, 2) void lprintf(const char *,...)
{
  // No stdout on some WinCE devices?
}
// msg() function is disabled too (see dumb.cpp)
#else
AS_PRINTF(1, 2) void lprintf(const char *format,...)
{
  va_list va;
  va_start(va, format);
  qvprintf(format, va);
  fflush(stdout);
  va_end(va);
}
#endif
