
#include <pro.h>
#include "linux_debmod.h"
//--------------------------------------------------------------------------
pid_t linux_debmod_t::check_for_signal(int _pid, int *status, int timeout_ms)
{
  return qwait_timed(_pid, status, __WALL | WCONTINUED, timeout_ms);
}
