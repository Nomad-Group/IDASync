#include <sys/sysctl.h>
#include <mach/mach.h>

#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include "macbase_debmod.h"

//--------------------------------------------------------------------------
inline const char *str_bitness(int bitness)
{
  switch ( bitness )
  {
    case 8:
      return "[64]";
    case 4:
      return "[32]";
    default:
      return "[?]";
  }
}

//--------------------------------------------------------------------------
cpu_type_t macbase_debmod_t::get_process_cpu(pid_t _pid)
{
  int mib[CTL_MAXNAME];
  size_t mibLen = CTL_MAXNAME;
  int err = sysctlnametomib("sysctl.proc_cputype", mib, &mibLen);
  if ( err == 0 )
  {
    QASSERT(895, mibLen < CTL_MAXNAME);
    mib[mibLen] = _pid;
    mibLen += 1;
    cpu_type_t cpu_type;
    size_t cpuTypeSize = sizeof(cpu_type);
    err = sysctl(mib, mibLen, &cpu_type, &cpuTypeSize, 0, 0);
    if ( err == 0 )
      return cpu_type;
  }
  msg("error from sysctl: %s\n", strerror(errno));
  return 0;
}

//--------------------------------------------------------------------------
static void build_process_ext_name(ext_process_info_t *pinfo)
{
  pinfo->ext_name = str_bitness(pinfo->addrsize);
  pinfo->ext_name.append(' ');
  pinfo->ext_name.append(pinfo->name);
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
bool idaapi macbase_debmod_t::get_exec_fname(
        int _pid,
        char *buf, size_t bufsize)
{
  int mib[3];
  mib[0] = CTL_KERN;
  mib[1] = KERN_ARGMAX;

  int argmax = 0;
  size_t size = sizeof(argmax);

  sysctl(mib, 2, &argmax, &size, NULL, 0);
  if ( argmax <= 0 )
    argmax = QMAXPATH;

  char *args = (char *)qalloc(argmax);
  if ( args == NULL )
    nomem("get_exec_fname");

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROCARGS2;
  mib[2] = _pid;

  // obtain the arguments for the target process. this will
  // only work for processes that belong to the current uid,
  // so if you want it to work universally, you need to run
  // as root.
  size = argmax;
  buf[0] = '\0';
  if ( sysctl(mib, 3, args, &size, NULL, 0) != -1 )
  {
    char *ptr = args + sizeof(int);
//    show_hex(ptr, size, "procargs2\n");

    qstrncpy(buf, ptr, bufsize);
  }
  qfree(args);
  return true;
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi macbase_debmod_t::get_process_bitness(int _pid)
{
  return get_cpu_bitness(get_process_cpu(_pid));
}

//--------------------------------------------------------------------------
int idaapi macbase_debmod_t::get_process_list(procvec_t *list)
{
  list->clear();
  int mypid = getpid();
  int sysControl[4];
  sysControl[0] = CTL_KERN;
  sysControl[1] = KERN_PROC;
  sysControl[2] = KERN_PROC_ALL;

  qvector<struct kinfo_proc> info;
  size_t length;
  int count = 0;
  int rc = -1;
  for ( int tries=0; rc != 0 && tries < 5; ++tries )
  {
    // the first call of sysctl() is used to determine the size of the buffer
    // will be passed to the second call
    length = 0;
    sysctl(sysControl, 3, NULL, &length, NULL, 0);

    // If the number of processes is greater than the size of the buffer
    // sysctl() supplies as much data as fits in the buffer and returns ENOMEM.
    // We reserve 100 extra elements for processes started after 1st sysctl
    // In case even this number is not sufficient we turn to the next attempt
    count = (length / sizeof (info[0])) + 100;
    if ( count <= 0 )
      return 0;
    if ( info.size() < count )
      info.resize(count);
    length = sizeof(info[0]) * info.size();
    rc = sysctl(sysControl, 3, info.begin(), &length, NULL, 0);
    if ( rc != 0 && errno != ENOMEM )
      return 0;
  }

  count = (length / sizeof (info[0])); // exact number of processes
  for ( int i=0; i < count; i++ )
  {
    extern_proc &ep = info[i].kp_proc;
    pid_t _pid = ep.p_pid;
    if ( _pid == mypid )
      continue;
    mach_port_t port;
    kern_return_t result = task_for_pid(mach_task_self(), _pid,  &port);
    if ( result == KERN_SUCCESS )
    {
      ext_process_info_t &pi = list->push_back();
      qstrncpy(pi.name, ep.p_comm, sizeof(pi.name));
      pi.pid = _pid;
      pi.addrsize = get_process_bitness(_pid);
      build_process_ext_name(&pi);
    }
    else
    {
      debdeb("%d: %s is unavailable for debugging\n", _pid, info[i].kp_proc.p_comm);
    }
  }
  return list->size();
}
