//
//
//      This file contains win32 specific implementations of win32_debugger_module class
//      server-side functionality only
//
//

#include <pro.h>
#include "win32_rpc.h"
#include "win32_debmod.h"
#include "rpc_hlp.h"

#ifdef ENABLE_REMOTEPDB

#include "tilfuncs.hpp"

//---------------------------------------------------------- main thread ---
static AS_PRINTF(3, 4) int pdb_ioctl_error(void **poutbuf, ssize_t *poutsize, const char *format, ...)
{
  char buf[MAXSTR];
  va_list va;
  va_start(va, format);
  int len = qvsnprintf(buf, sizeof(buf), format, va);
  va_end(va);
  msg("%s", buf);

  *poutsize = len + 1;
  *poutbuf  = qstrdup(buf);
  return pdb_error;
}

//---------------------------------------------------------- main thread ---
void win32_debmod_t::handle_pdb_thread_request(void *_fetcher)
{
  pdb_fetcher_t *fetcher = (pdb_fetcher_t *) _fetcher;
  pdb_thread_t &thr = fetcher->pdb_thread;
  if ( thr.read_request.kind == pdb_thread_t::read_request_t::READ_INPUT_FILE )
  {
    // read input file
    bytevec_t req;
    append_dq(req,  thr.read_request.off_ea);
    append_dd(req,  thr.read_request.size);
    append_str(req, fetcher->args.input_path);
    void *outbuf = NULL;
    ssize_t outsize = 0;
    // send request to IDA
    int rc = send_ioctl(WIN32_IOCTL_READFILE, req.begin(), req.size(), &outbuf, &outsize);
    if ( rc == 1 && outbuf != NULL )
    {
      // OK
      size_t copylen = qmin(thr.read_request.size, outsize);
      memcpy(thr.read_request.buffer, outbuf, copylen);
      thr.read_request.size   = copylen;
      thr.read_request.result = true;
    }
    else
    {
      thr.read_request.result = false;
    }
    if ( outbuf != NULL )
      qfree(outbuf);
  }
  else if ( thr.read_request.kind == pdb_thread_t::read_request_t::READ_MEMORY )
  {
    // read memory
    ea_t ea = ea_t(thr.read_request.off_ea);
    void *buf = thr.read_request.buffer;
    size_t size = thr.read_request.size;
    ssize_t rc = _read_memory(ea, buf, size);
    if ( rc >= 0 )
      thr.read_request.size = rc;
    thr.read_request.result = rc >= 0;
  }
  else
  {
    // unknown request
    thr.read_request.result = false;
  }

  fetcher->pdb_thread.read_request.req_complete();
}

//----------------------------------------------------------------------------
struct pdb_remote_session_t
{
  ~pdb_remote_session_t()
  {
    fetcher.stop_pdb_thread();
    if ( fetcher.pdb_thread.is_running() )
      fetcher.pdb_thread.kill();
  }

  local_pdb_access_t *get_pdb_access() const
  {
    return fetcher.session_ref.session->pdb_access;
  }

  pdb_fetcher_t fetcher;
};

//----------------------------------------------------------------------------
void close_pdb_remote_session(pdb_remote_session_t *session)
{
  delete session;
}

#else

void close_pdb_remote_session(pdb_remote_session_t *)
{
}

#endif

//---------------------------------------------------------- main thread ---
int idaapi win32_debmod_t::handle_ioctl(
      int fn,
      const void *buf,
      size_t size,
      void **poutbuf,
      ssize_t *poutsize)
{
  qnotused(size);
  switch ( fn )
  {
    case WIN32_IOCTL_RDMSR:
      QASSERT(30119, size == sizeof(uval_t));
      {
        uint64 value;
        uval_t reg = *(uval_t *)buf;
        int code = rdmsr(reg, &value);
        if ( SUCCEEDED(code) )
        {
          *poutbuf = qalloc(sizeof(value));
          if ( *poutbuf != NULL )
          {
            memcpy(*poutbuf, &value, sizeof(value));
            *poutsize = sizeof(value);
          }
        }
        return code;
      }

    case WIN32_IOCTL_WRMSR:
      QASSERT(30120, size == sizeof(win32_wrmsr_t));
      {
        win32_wrmsr_t &msr = *(win32_wrmsr_t *)buf;
        return wrmsr(msr.reg, msr.value);
      }

#ifdef ENABLE_REMOTEPDB
    case WIN32_IOCTL_PDB_OPEN:
      {
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;

        pdb_remote_session = new pdb_remote_session_t();

        compiler_info_t cci;
        extract_memory(&ptr, end, &cci, sizeof(cci));
        pdbargs_t args;
        args.pdb_path = extract_str(&ptr, end);
        args.input_path = extract_str(&ptr, end);
        extract_memory(&ptr, end, &args.pdb_sign, sizeof(args.pdb_sign));
        args.spath = extract_str(&ptr, end);
        args.loaded_base = extract_ea64(&ptr, end);
        args.flags = extract_long(&ptr, end);
        pdb_remote_session->fetcher.start_thread(cci, args);
        *poutsize = 0;
        *poutbuf  = NULL;
      }
      return pdb_ok;

    case WIN32_IOCTL_PDB_OPERATION_COMPLETE:
      // This is used, in a polling fashion, by the the client,
      // to check on completeness of the fetch. At the same time,
      // this is our wake-up call for looking whether the
      // fetch thread requires more information.
      {
        if ( pdb_remote_session == NULL )
          return pdb_ioctl_error(poutbuf, poutsize, "Failed to open a session\n");

        // If we've got a read request, handle it now
        if ( pdb_remote_session->fetcher.pdb_thread.read_request.pending() )
          handle_pdb_thread_request(&pdb_remote_session->fetcher);

        if ( !pdb_remote_session->fetcher.pdb_thread.is_done() )
          return pdb_operation_incomplete;

        const char *fname = pdb_remote_session->fetcher.session_ref.session->get_used_fname();
        HRESULT hr = pdb_remote_session->fetcher.pdb_thread.result.hr;
        if ( SUCCEEDED(hr) )
        {
          bytevec_t storage;
          local_pdb_access_t *acc = pdb_remote_session->get_pdb_access();
          append_dd(storage, acc->get_global_symbol_id());
          append_dd(storage, acc->get_machine_type());
          append_dd(storage, acc->get_dia_version());
          append_str(storage, fname);
          *poutsize = storage.size();
          *poutbuf  = storage.extract();
          return pdb_operation_complete;
        }
        else
        {
          int code = pdb_ioctl_error(poutbuf, poutsize,
                                     "%s: %s\n",
                                     fname,
                                     pdberr(hr));
          delete pdb_remote_session;
          pdb_remote_session = NULL;
          return code;
        }
      }

    case WIN32_IOCTL_PDB_FETCH_SYMBOL:
    case WIN32_IOCTL_PDB_FETCH_CHILDREN:
      {
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;

        DWORD sym_id = extract_long(&ptr, end);

        // msg("Fetch%s 0x%x\n",
        //     (fn == WIN32_IOCTL_PDB_FETCH_CHILDREN ? " children for" : ""),
        //     (uint32) sym);

        if ( pdb_remote_session == NULL )
          return pdb_ioctl_error(poutbuf, poutsize, "Session not opened\n");

        bool ok;
        if ( fn == WIN32_IOCTL_PDB_FETCH_SYMBOL )
        {
          // Symbol
          ok = pdb_remote_session->fetcher.fetch_symbol(sym_id);
        }
        else
        {
          // Children
          enum SymTagEnum children_type = (enum SymTagEnum)extract_long(&ptr, end);
          ok = pdb_remote_session->fetcher.fetch_children(sym_id, children_type);
        }

        if ( ok )
        {
          size_t sz  = pdb_remote_session->fetcher.storage.size();
          uint8 *raw = (uint8 *) qalloc(sz);
          if ( raw == NULL )
            return pdb_error;
          memcpy(raw, pdb_remote_session->fetcher.storage.begin(), sz);
          *poutbuf   = raw;
          *poutsize  = sz;
        }

        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_CLOSE:
      {
        // msg("Closing session\n");
        if ( pdb_remote_session == NULL )
          return pdb_ioctl_error(poutbuf, poutsize, "Session not opened\n");

        delete pdb_remote_session;
        pdb_remote_session = NULL;

        return pdb_ok;
      }


#endif // ENABLE_REMOTEPDB

    default:
      break;
  }
  return 0;
}
