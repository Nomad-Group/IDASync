#ifdef USE_ASYNC
#include "async.h"
#include <err.h>
#else
#include "tcpip.h"      // otherwise can not compile win32_remote.bpr
#endif
#include <limits.h>
#include <typeinf.hpp>
#include "server.h"


//--------------------------------------------------------------------------
// another copy of this function (for local debugging) is defined in common_local_impl.cpp
int send_ioctl(
        rpc_engine_t *srv,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return srv->send_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
ssize_t dvmsg(int code, rpc_engine_t *rpc, const char *format, va_list va)
{
  if ( code == 0 )
    code = RPC_MSG;
  else if ( code > 0 )
    code = RPC_WARNING;
  else
    code = RPC_ERROR;

  bytevec_t req = prepare_rpc_packet((uchar)code);

  char buf[MAXSTR];
  qvsnprintf(buf, sizeof(buf), format, va);
  append_str(req, buf);

  qfree(rpc->process_request(req));
  if ( code < 0 ) // RPC_ERROR
    exit(1);
  return strlen(buf);
}

//--------------------------------------------------------------------------
void report_idc_error(rpc_engine_t *rpc, ea_t ea, error_t code, ssize_t errval, const char *errprm)
{
  if ( code == eOS )
  {
    rpc_server_t *server = (rpc_server_t *)rpc;
    errval = server->get_debugger_instance()->get_system_specific_errno();
  }

  bytevec_t req = prepare_rpc_packet(RPC_REPORT_IDC_ERROR);
  append_ea64(req, ea);
  append_dd(req, code);
  if ( (const char *)errval == errprm )
  {
    append_db(req, 1);
    append_str(req, errprm);
  }
  else
  {
    append_db(req, 0);
    append_ea64(req, errval);
  }
  qfree(rpc->process_request(req));
}

//--------------------------------------------------------------------------
debmod_t *rpc_server_t::get_debugger_instance()
{
  return dbg_mod;
}

//--------------------------------------------------------------------------
void rpc_server_t::prepare_broken_connection(void)
{
  if ( debmod_t::reuse_broken_connections )
  {
    if ( !dbg_mod->dbg_prepare_broken_connection() )
      dmsg("Error preparing debugger server to handle a broken connection\n");
  }
}

//--------------------------------------------------------------------------
rpc_server_t::~rpc_server_t()
{
  //lint -e(1506) Call to virtual function 'rpc_server_t::get_broken_connection(void)' within a constructor or destructor
  if ( !get_broken_connection() )
    delete dbg_mod; // the connection is not broken, delete the debugger instance

  //lint -esym(1579,rpc_server_t::dbg_mod) pointer member might have been freed by a separate function
  clear_channels();
}

//--------------------------------------------------------------------------
void rpc_server_t::set_debugger_instance(debmod_t *instance)
{
  dbg_mod = instance;
  dbg_mod->rpc = this;
}

//--------------------------------------------------------------------------
void rpc_server_t::close_all_channels()
{
  for ( int i=0; i < qnumber(channels); i++ )
    if ( channels[i] != NULL )
      qfclose(channels[i]);

  clear_channels();
}

//--------------------------------------------------------------------------
void rpc_server_t::clear_channels()
{
  memset(channels, 0, sizeof(channels));
}

//--------------------------------------------------------------------------
int rpc_server_t::find_free_channel() const
{
  for ( int i=0; i < qnumber(channels); i++ )
    if ( channels[i] == NULL )
      return i;
  return -1;
}

//--------------------------------------------------------------------------
#ifdef VERBOSE_ENABLED
static const char *bptcode2str(uint code)
{
  static const char *const strs[] =
  {
    "BPT_OK",
    "BPT_INTERNAL_ERR",
    "BPT_BAD_TYPE",
    "BPT_BAD_ALIGN",
    "BPT_BAD_ADDR",
    "BPT_BAD_LEN",
    "BPT_TOO_MANY",
    "BPT_READ_ERROR",
    "BPT_WRITE_ERROR",
    "BPT_SKIP",
    "BPT_PAGE_OK",
  };
  if ( code >= qnumber(strs) )
    return "?";
  return strs[code];
}
#endif

//--------------------------------------------------------------------------
int rpc_server_t::rpc_update_bpts(
        const uchar *ptr,
        const uchar *end,
        bytevec_t &req)
{
  update_bpt_vec_t bpts;
  int nadd = extract_long(&ptr, end);
  int ndel = extract_long(&ptr, end);

  if ( nadd < 0 || ndel < 0 || INT_MAX - ndel < nadd )
  {
    append_dd(req, 0);
    verb(("update_bpts(nadd=%d, ndel=%d) => 0 (incorrect values)\n", nadd, ndel));
    return 0;
  }

  bpts.resize(nadd+ndel);
  ea_t ea = 0;
  update_bpt_vec_t::iterator b;
  update_bpt_vec_t::iterator bend = bpts.begin() + nadd;
  for ( b=bpts.begin(); b != bend; ++b )
  {
    b->code = BPT_OK;
    b->ea = ea + extract_ea64(&ptr, end); ea = b->ea;
    b->size = extract_long(&ptr, end);
    b->type = extract_long(&ptr, end);
  }

  ea = 0;
  bend += ndel;
  for ( ; b != bend; ++b )
  {
    b->ea = ea + extract_ea64(&ptr, end); ea = b->ea;
    uchar len = extract_byte(&ptr, end);
    if ( len > 0 )
    {
      b->orgbytes.resize(len);
      extract_memory(&ptr, end, b->orgbytes.begin(), len);
    }
    b->type = extract_long(&ptr, end);
  }

#ifdef VERBOSE_ENABLED
  for ( b=bpts.begin()+nadd; b != bend; ++b )
    verb(("del_bpt(ea=%a, type=%d orgbytes.size=%" FMT_Z " size=%d)\n",
          b->ea, b->type, b->orgbytes.size(), b->type != BPT_SOFT ? b->size : 0));
#endif

  int ret = dbg_mod->dbg_update_bpts(bpts.begin(), nadd, ndel);

  bend = bpts.begin() + nadd;
#ifdef VERBOSE_ENABLED
  for ( b=bpts.begin(); b != bend; ++b )
    verb(("add_bpt(ea=%a type=%d len=%d) => %s\n", b->ea, b->type, b->size, bptcode2str(b->code)));
#endif

  append_dd(req, ret);
  for ( b=bpts.begin(); b != bend; ++b )
  {
    append_db(req, b->code);
    if ( b->code == BPT_OK && b->type == BPT_SOFT )
    {
      append_db(req, b->orgbytes.size());
      append_memory(req, b->orgbytes.begin(), b->orgbytes.size());
    }
  }

  bend += ndel;
  for ( ; b != bend; ++b )
  {
    append_db(req, b->code);
    verb(("del_bpt(ea=%a) => %s\n", b->ea, bptcode2str(b->code)));
  }

  return ret;
}

//--------------------------------------------------------------------------
int rpc_server_t::rpc_update_lowcnds(
        const uchar *ptr,
        const uchar *end)
{
  ea_t ea = 0;
  lowcnd_vec_t lowcnds;
  int nlowcnds = extract_long(&ptr, end);
  lowcnds.resize(nlowcnds);
  lowcnd_t *lc = lowcnds.begin();
  for ( int i=0; i < nlowcnds; i++, lc++ )
  {
    lc->compiled = false;
    lc->ea = ea + extract_ea64(&ptr, end); ea = lc->ea;
    lc->cndbody = extract_str(&ptr, end);
    if ( !lc->cndbody.empty() )
    {
      lc->size = 0;
      lc->type = extract_long(&ptr, end);
      if ( lc->type != BPT_SOFT )
        lc->size = extract_long(&ptr, end);
      int norg = extract_byte(&ptr, end);
      if ( norg > 0 )
      {
        lc->orgbytes.resize(norg);
        extract_memory(&ptr, end, lc->orgbytes.begin(), norg);
      }
      lc->cmd.ea = extract_ea64(&ptr, end);
      if ( lc->cmd.ea != BADADDR )
        extract_memory(&ptr, end, &lc->cmd, sizeof(lc->cmd));
    }
    verb(("update_lowcnd(ea=%a cnd=%s)\n", ea, lc->cndbody.c_str()));
  }
  int ret = dbg_mod->dbg_update_lowcnds(lowcnds.begin(), nlowcnds);
  verb(("  update_lowcnds => %d\n", ret));

  return ret;
}

//--------------------------------------------------------------------------
bool rpc_server_t::check_broken_connection(pid_t pid)
{
  bool result = false;
  srv_lock_begin();
  rpc_server_list_t::iterator p;
  for ( p = clients_list.begin(); p != clients_list.end(); ++p )
  {
    rpc_server_t *server = p->first;
    if ( server == this )
      continue;

    debmod_t *d = server->get_debugger_instance();
    if ( d->broken_connection && d->pid == pid && d->dbg_continue_broken_connection(pid) )
    {
      dbg_mod->dbg_term();
      delete dbg_mod;
      dbg_mod = d;
      result = true;
      verb(("reusing previously broken debugging session\n"));

#ifndef __SINGLE_THREADED_SERVER__
      qthread_t thr = p->second;

      // free thread
      if ( thr != NULL )
        qthread_free(thr);
#endif

      server->term_irs();
      clients_list.erase(p);
      delete server;

      d->broken_connection = false;
      break;
    }
  }
  srv_lock_end();
  return result;
}

//-------------------------------------------------------------------------
int rpc_server_t::handle_server_ioctl(int, const void *, size_t, void **, ssize_t *) { return -1; }

//--------------------------------------------------------------------------
int rpc_server_t::rpc_attach_process(
        const uchar *ptr,
        const uchar *end)
{
  pid_t pid = extract_long(&ptr, end);
  int event_id = extract_long(&ptr, end);
  int flags = extract_long(&ptr, end);
  bool result = check_broken_connection(pid);
  if ( !result )
    result = dbg_mod->dbg_attach_process(pid, event_id, flags) > 0;
  verb(("attach_process(pid=%d, evid=%d) => %d\n", pid, event_id, result));
  return result;
}

//-------------------------------------------------------------------------
void rpc_server_t::append_start_or_attach(bytevec_t &req, int result) const
{
  append_dd(req, result);
  if ( result > 0 )
  {
    debapp_attrs_t attrs;
    dbg_mod->dbg_get_debapp_attrs(&attrs);
    append_debapp_attrs(req, &attrs);
  }
}

//--------------------------------------------------------------------------
// performs requests on behalf of a remote client
// client -> server
bytevec_t rpc_server_t::perform_request(const rpc_packet_t *rp)
{
  // While the server is performing a request, it should not poll
  // for debugger events
  bool saved_poll_mode = poll_debug_events;
  poll_debug_events = false;

  const uchar *ptr = (const uchar *)(rp + 1);
  const uchar *end = ptr + rp->length;
  bytevec_t req = prepare_rpc_packet(RPC_OK);
#if defined(__EXCEPTIONS) || defined(__NT__)
  try
#endif
  {
    switch ( rp->code )
    {
      case RPC_INIT:
        {
          dbg_mod->debugger_flags = extract_long(&ptr, end);
          bool debug_debugger = extract_long(&ptr, end) != 0;
          if ( debug_debugger )
            verbose = true;

          dbg_mod->dbg_set_debugging(debug_debugger);
          int result = dbg_mod->dbg_init();
          verb(("init(debug_debugger=%d) => %d\n", debug_debugger, result));
          append_dd(req, result);
        }
        break;

      case RPC_TERM:
        // Do not dbg_term() here, as it will be called
        // at the end of server.cpp's handle_single_session(),
        // right after this.
        // dbg_mod->dbg_term();
        // verb(("term()\n"));
        break;

      case RPC_GET_PROCESSES:
        {
          procinfo_vec_t procs;
          bool result = dbg_mod->dbg_get_processes(&procs) > 0;
          append_dd(req, result);
          if ( result )
            append_process_info_vec(req, &procs);
          verb(("get_processes() => %d\n", result));
        }
        break;

      case RPC_DETACH_PROCESS:
        {
          int result = dbg_mod->dbg_detach_process();
          append_dd(req, result);
          verb(("detach_process() => %d\n", result));
        }
        break;

      case RPC_START_PROCESS:
        {
          char *path = extract_str(&ptr, end);
          char *args = extract_str(&ptr, end);
          char *sdir = extract_str(&ptr, end);
          int flags  = extract_long(&ptr, end);
          char *input= extract_str(&ptr, end);
          uint32 crc32= extract_long(&ptr, end);
          int result = dbg_mod->dbg_start_process(path, args, sdir, flags, input, crc32);
          verb(("start_process(path=%s args=%s flags=%s%s%s\n"
            "              sdir=%s\n"
            "              input=%s crc32=%x) => %d\n",
            path, args,
            flags & DBG_PROC_IS_DLL ? " is_dll" : "",
            flags & DBG_PROC_IS_GUI ? " under_gui" : "",
            flags & DBG_HIDE_WINDOW ? " hide_window" : "",
            sdir,
            input, crc32,
            result));
          append_start_or_attach(req, result);
        }
        break;

      case RPC_GET_DEBUG_EVENT:
        {
          int timeout_ms = extract_long(&ptr, end);
          gdecode_t result = GDE_NO_EVENT;
          if ( !has_pending_event )
            result = dbg_mod->dbg_get_debug_event(&ev, timeout_ms);
          append_dd(req, result);
          if ( result >= GDE_ONE_EVENT )
          {
            append_debug_event(req, &ev);
            verb(("got event: %s\n", debug_event_str(&ev)));
          }
          else if ( !has_pending_event )
          {
            saved_poll_mode = true;
          }
          verbev(("get_debug_event(timeout=%d) => %d (has_pending=%d, willpoll=%d)\n", timeout_ms, result, has_pending_event, saved_poll_mode));
        }
        break;

      case RPC_ATTACH_PROCESS:
        append_start_or_attach(req, rpc_attach_process(ptr, end));
        break;

      case RPC_PREPARE_TO_PAUSE_PROCESS:
        {
          int result = dbg_mod->dbg_prepare_to_pause_process();
          verb(("prepare_to_pause_process() => %d\n", result));
          append_dd(req, result);
        }
        break;

      case RPC_EXIT_PROCESS:
        {
          int result = dbg_mod->dbg_exit_process();
          verb(("exit_process() => %d\n", result));
          append_dd(req, result);
        }
        break;

      case RPC_CONTINUE_AFTER_EVENT:
        {
          extract_debug_event(&ptr, end, &ev);
          int result = dbg_mod->dbg_continue_after_event(&ev);
          verb(("continue_after_event(...) => %d\n", result));
          append_dd(req, result);
        }
        break;

      case RPC_STOPPED_AT_DEBUG_EVENT:
        {
          dbg_mod->dbg_stopped_at_debug_event();
          name_info_t *ni = dbg_mod->get_debug_names();
          int err = RPC_OK;
          if ( ni != NULL )
          {
            err = send_debug_names_to_ida(ni->addrs.begin(), ni->names.begin(), (int)ni->addrs.size());
            dbg_mod->clear_debug_names();
          }
          verb(("stopped_at_debug_event => %s\n", get_rpc_name(err)));
          break;
        }

      case RPC_TH_SUSPEND:
        {
          thid_t tid = extract_long(&ptr, end);
          int result = dbg_mod->dbg_thread_suspend(tid);
          verb(("thread_suspend(tid=%d) => %d\n", tid, result));
          append_dd(req, result);
        }
        break;

      case RPC_TH_CONTINUE:
        {
          thid_t tid = extract_long(&ptr, end);
          int result = dbg_mod->dbg_thread_continue(tid);
          verb(("thread_continue(tid=%d) => %d\n", tid, result));
          append_dd(req, result);
        }
        break;

      case RPC_SET_RESUME_MODE:
        {
          thid_t tid = extract_long(&ptr, end);
          resume_mode_t resmod = resume_mode_t(extract_long(&ptr, end));
          int result = dbg_mod->dbg_set_resume_mode(tid, resmod);
          verb(("set_resume_mode(tid=%d, resmod=%d) => %d\n", tid, resmod, result));
          append_dd(req, result);
        }
        break;

      case RPC_READ_REGS:
        {
          thid_t tid  = extract_long(&ptr, end);
          int clsmask = extract_long(&ptr, end);
          int nregs   = extract_long(&ptr, end);
          if ( nregs <= 0 || nregs > dbg_mod->nregs )
          {
            append_dd(req, 0);
            verb(("read_regs(tid=%d, mask=%x, nregs=%d) => 0 (incorrect nregs, should be in range 0..%d)\n", tid, clsmask, nregs, dbg_mod->nregs));
            break;
          }
          bytevec_t regmap;
          regmap.resize((nregs+7)/8);
          extract_memory(&ptr, end, regmap.begin(), regmap.size());
          regval_t *values = OPERATOR_NEW(regval_t, dbg_mod->nregs);
          int result = dbg_mod->dbg_read_registers(tid, clsmask, values);
          verb(("read_regs(tid=%d, mask=%x) => %d\n", tid, clsmask, result));
          append_dd(req, result);
          if ( result )
            append_regvals(req, values, nregs, regmap.begin());
          delete[] values;
        }
        break;

      case RPC_WRITE_REG:
        {
          thid_t tid = extract_long(&ptr, end);
          int reg_idx = extract_long(&ptr, end);
          regval_t value;
          extract_regvals(&ptr, end, &value, 1, NULL);
          int result = dbg_mod->dbg_write_register(tid, reg_idx, &value);
          verb(("write_reg(tid=%d) => %d\n", tid, result));
          append_dd(req, result);
        }
        break;

      case RPC_GET_SREG_BASE:
        {
          thid_t tid = extract_long(&ptr, end);
          int sreg_value = extract_long(&ptr, end);
          ea_t ea;
          int result = dbg_mod->dbg_thread_get_sreg_base(&ea, tid, sreg_value);
          verb(("get_thread_sreg_base(tid=%d, %d) => %a\n", tid, sreg_value, result ? ea : BADADDR));
          append_dd(req, result);
          if ( result )
            append_ea64(req, ea);
        }
        break;

      case RPC_SET_EXCEPTION_INFO:
        {
          int qty = extract_long(&ptr, end);
          exception_info_t *extable = extract_exception_info(&ptr, end, qty);
          dbg_mod->dbg_set_exception_info(extable, qty);
          delete [] extable;
          verb(("set_exception_info(qty=%d)\n", qty));
        }
        break;

      case RPC_GET_MEMORY_INFO:
        {
          meminfo_vec_t areas;
          int result = dbg_mod->dbg_get_memory_info(areas);
          int qty = areas.size();
          verb(("get_memory_info() => %d (qty=%d)\n", result, qty));
          append_dd(req, result+2);
          if ( result > 0 )
          {
            append_dd(req, qty);
            for ( int i=0; i < qty; i++ )
              append_memory_info(req, &areas[i]);
          }
        }
        break;

      case RPC_GET_SCATTERED_IMAGE:
        {
          ea_t base = extract_ea64(&ptr, end);
          scattered_image_t si;
          int result = dbg_mod->dbg_get_scattered_image(si, base);
          int qty = si.size();
          verb(("get_scattered_image(base=%a) => %d (qty=%d)\n", base, result, qty));
          append_dd(req, result+2);
          if ( result > 0 )
          {
            append_dd(req, qty);
            for ( int i=0; i < qty; i++ )
              append_scattered_segm(req, &si[i]);
          }
        }
        break;

      case RPC_GET_IMAGE_UUID:
        {
          ea_t base = extract_ea64(&ptr, end);
          bytevec_t uuid;
          bool result = dbg_mod->dbg_get_image_uuid(&uuid, base);
          int qty = uuid.size();
          verb(("get_image_uuid(base=%a) => %d (qty=%d)\n", base, result, qty));
          append_dd(req, result);
          if ( result )
            append_buf(req, uuid.begin(), qty);
        }
        break;

      case RPC_GET_SEGM_START:
        {
          ea_t base = extract_ea64(&ptr, end);
          const char *segname = extract_str(&ptr, end);
          ea_t result = dbg_mod->dbg_get_segm_start(base, segname);
          verb(("get_segm_start(base=%a, segname=%s) => %a\n", base, segname, result));
          append_ea64(req, result);
        }
        break;

      case RPC_READ_MEMORY:
        {
          ea_t ea = extract_ea64(&ptr, end);
          size_t size = extract_long(&ptr, end);
          uchar *buf = new uchar[size];
          ssize_t result = dbg_mod->dbg_read_memory(ea, buf, size);
          verb(("read_memory(ea=%a size=%" FMT_Z ") => %" FMT_ZS, ea, size, result));
          if ( result > 0 && size == 1 )
            verb((" (0x%02X)\n", *buf));
          else
            verb(("\n"));
          append_dd(req, uint32(result));
          if ( result > 0 )
            append_memory(req, buf, result);
          delete[] buf;
        }
        break;

      case RPC_WRITE_MEMORY:
        {
          ea_t ea = extract_ea64(&ptr, end);
          size_t size = extract_long(&ptr, end);
          uchar *buf = new uchar[size];
          extract_memory(&ptr, end, buf, size);
          ssize_t result = dbg_mod->dbg_write_memory(ea, buf, size);
          verb(("write_memory(ea=%a size=%" FMT_Z ") => %" FMT_ZS, ea, size, result));
          if ( result && size == 1 )
            verb((" (0x%02X)\n", *buf));
          else
            verb(("\n"));
          append_dd(req, uint32(result));
          delete[] buf;
        }
        break;

      case RPC_ISOK_BPT:
        {
          bpttype_t type = extract_long(&ptr, end);
          ea_t ea        = extract_ea64(&ptr, end);
          int len        = extract_long(&ptr, end) - 1;
          int result = dbg_mod->dbg_is_ok_bpt(type, ea, len);
          verb(("isok_bpt(type=%d ea=%a len=%d) => %d\n", type, ea, len, result));
          append_dd(req, result);
        }
        break;

      case RPC_UPDATE_BPTS:
        {
          int ret = rpc_update_bpts(ptr, end, req);
          if ( ret == 0 )
            verb(("rpc_update_bpts failed!\n"));
        }
        break;

      case RPC_UPDATE_LOWCNDS:
        {
          int ret = rpc_update_lowcnds(ptr, end);
          append_dd(req, ret);
        }
        break;

      case RPC_EVAL_LOWCND:
        {
          thid_t tid = extract_long(&ptr, end);
          ea_t ea    = extract_ea64(&ptr, end);
          int ret = dbg_mod->dbg_eval_lowcnd(tid, ea);
          append_dd(req, ret);
          verb(("eval_lowcnd(tid=%d, ea=%a) => %d\n", tid, ea, ret));
        }
        break;

      case RPC_OPEN_FILE:
        {
          char *file = extract_str(&ptr, end);
          bool readonly = extract_long(&ptr, end) != 0;
          int64 fsize = 0;
          int fn = find_free_channel();
          if ( fn != -1 )
          {
            channels[fn] = (readonly ? fopenRB : fopenWB)(file);
            if ( channels[fn] == NULL )
              fn = -1;
            else if ( readonly )
              fsize = qfsize(channels[fn]);
          }
          verb(("open_file('%s', %d) => %d %" FMT_64 "d\n", file, readonly, fn, fsize));
          append_dd(req, fn);
          if ( fn != -1 )
            append_dq(req, fsize);
          else
            append_dd(req, qerrcode());
        }
        break;

      case RPC_CLOSE_FILE:
        {
          int fn = extract_long(&ptr, end);
          if ( fn >= 0 && fn < qnumber(channels) )
          {
#ifdef __UNIX__
            // set mode 0755 for unix applications
            fchmod(fileno(channels[fn]), S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
#endif
            qfclose(channels[fn]);
            channels[fn] = NULL;
          }
          verb(("close_file(%d)\n", fn));
        }
        break;

      case RPC_READ_FILE:
        {
          char *buf  = NULL;
          int fn     = extract_long(&ptr, end);
          int64 off  = extract_uint64(&ptr, end);
          int32 size = extract_long(&ptr, end);
          int32 s2 = 0;
          if ( size > 0 )
          {
            buf = new char[size];
            qfseek(channels[fn], off, SEEK_SET);
            s2 = qfread(channels[fn], buf, size);
          }
          append_dd(req, s2);
          if ( size != s2 )
            append_dd(req, qerrcode());
          if ( s2 > 0 )
            append_memory(req, buf, s2);
          delete[] buf;
          verb(("read_file(%d, 0x%" FMT_64 "X, %d) => %d\n", fn, off, size, s2));
        }
        break;

      case RPC_WRITE_FILE:
        {
          char *buf = NULL;
          int fn = extract_long(&ptr, end);
          uint64 off = extract_uint64(&ptr, end);
          uint32 size = extract_long(&ptr, end);
          if ( size > 0 )
          {
            buf = new char[size];
            extract_memory(&ptr, end, buf, size);
          }
          qfseek(channels[fn], off, SEEK_SET);
          uint32 s2 = buf == NULL ? 0 : qfwrite(channels[fn], buf, size);
          append_dd(req, size);
          if ( size != s2 )
            append_dd(req, qerrcode());
          delete [] buf;
          verb(("write_file(%d, 0x%" FMT_64 "X, %u) => %u\n", fn, off, size, s2));
        }
        break;

      case RPC_EVOK:
        req.clear();
        verbev(("got evok!\n"));
        break;

      case RPC_IOCTL:
        {
          int code = handle_ioctl_packet(req, ptr, end);
          if ( code != RPC_OK )
            req = prepare_rpc_packet((uchar)code);
        }
        break;

      case RPC_UPDATE_CALL_STACK:
        {
          call_stack_t trace;
          thid_t tid = extract_long(&ptr, end);
          bool ok = dbg_mod->dbg_update_call_stack(tid, &trace);
          append_dd(req, ok);
          if ( ok )
            append_call_stack(req, trace);
        }
        break;

      case RPC_APPCALL:
        {
          ea_t func_ea      = extract_ea64(&ptr, end);
          thid_t tid        = extract_long(&ptr, end);
          int stkarg_nbytes = extract_long(&ptr, end);
          int flags         = extract_long(&ptr, end);

          regobjs_t regargs, retregs;
          relobj_t stkargs;
          regobjs_t *rr = (flags & APPCALL_MANUAL) == 0 ? &retregs : NULL;
          extract_appcall(&ptr, end, &regargs, &stkargs, rr);

          qstring errbuf;
          debug_event_t event;
          ea_t sp = dbg_mod->dbg_appcall(func_ea, tid, stkarg_nbytes, &regargs, &stkargs,
                                          &retregs, &errbuf, &event, flags);
          append_ea64(req, sp);
          if ( sp == BADADDR )
          {
            if ( (flags & APPCALL_DEBEV) != 0 )
              append_debug_event(req, &event);
            append_str(req, errbuf);
          }
          else if ( (flags & APPCALL_MANUAL) == 0 )
          {
            append_regobjs(req, retregs, true);
          }
        }
        break;

      case RPC_CLEANUP_APPCALL:
        {
          thid_t tid = extract_long(&ptr, end);
          int code = dbg_mod->dbg_cleanup_appcall(tid);
          append_dd(req, code);
        }
        break;

      case RPC_REXEC:
        {
          const char *cmdline = extract_str(&ptr, end);
          int code = dbg_mod->dbg_rexec(cmdline);
          append_dd(req, code);
        }
        break;

      default:
        req = prepare_rpc_packet(RPC_UNK);
        break;
    }
  }
#if defined(__EXCEPTIONS) || defined(__NT__)
  catch ( const std::bad_alloc & )
  {
    req = prepare_rpc_packet(RPC_MEM);
  }
#endif

  if ( saved_poll_mode )
    poll_debug_events = true;
  return req;
}

//--------------------------------------------------------------------------
// poll for events from the debugger module
int rpc_server_t::poll_events(int timeout_ms)
{
  int code = 0;
  if ( !has_pending_event )
  {
    // immediately set poll_debug_events to false to avoid recursive calls.
    poll_debug_events = false;
    has_pending_event = dbg_mod->dbg_get_debug_event(&pending_event, timeout_ms) >= GDE_ONE_EVENT;
    if ( has_pending_event )
    {
      verbev(("got event, sending it, poll will be 0 now\n"));
      bytevec_t req = prepare_rpc_packet(RPC_EVENT);
      append_debug_event(req, &pending_event);
      code = send_request(req);
      has_pending_event = false;
    }
    else
    { // no event, continue to poll
      poll_debug_events = true;
    }
  }
  return code;
}

//--------------------------------------------------------------------------
// this function runs on the server side
// an rpc_client sends an RPC_SYNC request and the server must give the stub to the client
bool rpc_server_t::rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name)
{
  bool ok = false;
  int32 crc32 = -1;
  linput_t *li = open_linput(server_stub_name, false);
  if ( li != NULL )
  {
    crc32 = calc_file_crc32(li);
    close_linput(li);
  }

  bytevec_t stub = prepare_rpc_packet(RPC_SYNC_STUB);
  append_str(stub, ida_stub_name);
  append_dd(stub, crc32);
  rpc_packet_t *rp = process_request(stub);

  if ( rp == NULL )
    return ok;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  size_t size = extract_long(&answer, end);
  if ( size == 1 )
  {
    ok = true;
  }
  else if ( size != 0 )
  {
    FILE *fp = fopenWB(server_stub_name);
    if ( fp != NULL )
    {
      ok = qfwrite(fp, answer, size) == size;
      dmsg("Updated kernel debugger stub: %s\n", ok ? "success" : "failed");
      qfclose(fp);
    }
    else
    {
      dwarning("Could not update the kernel debugger stub.\n%s", qerrstr());
    }
  }
  qfree(rp);

  return ok;
}

//--------------------------------------------------------------------------
//lint -e{818} 'addrs' could be declared as pointing to const
int rpc_server_t::send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty)
{
  if ( qty == 0 )
    return RPC_OK;

  bytevec_t buf;

  const size_t SZPACKET = 1300; // try not to go over the usual network MSS
                                // (this number is slightly less that 1460 because
                                //  we stop the loop going over this number)
  while ( qty > 0 )
  {
    buf.qclear();

    ea_t old = 0;
    const char *optr = "";

    // Start appending names and EAs
    int i = 0;
    while ( i < qty )
    {
      adiff_t diff = *addrs - old;
      bool neg = diff < 0;
      if ( neg )
        diff = -diff;

      append_ea64(buf, diff); // send address deltas
      append_dd(buf, neg);

      old = *addrs;
      const char *nptr = *names;
      int len = 0;

      // do not send repeating prefixes of names
      while ( nptr[len] != '\0' && nptr[len] == optr[len] ) //lint !e690 wrong access
        len++;

      append_dd(buf, len);
      append_str(buf, nptr+len);
      optr = nptr;
      addrs++;
      names++;
      i++;

      if ( buf.size() > SZPACKET )
        break;
    }
    qty -= i;

    bytevec_t req = prepare_rpc_packet(RPC_SET_DEBUG_NAMES);
    append_dd(req, i);
    req.append(buf.begin(), buf.size());

    // should return a qty as much as sent...if not probably network error!
    if ( i != process_long(req) )
      return RPC_UNK;
  }

  return RPC_OK;
}

//--------------------------------------------------------------------------
int rpc_server_t::send_debug_event_to_ida(const debug_event_t *debev, int rqflags)
{
  bytevec_t req = prepare_rpc_packet(RPC_HANDLE_DEBUG_EVENT);
  append_debug_event(req, debev);
  append_dd(req, rqflags);
  return process_long(req);
}

//--------------------------------------------------------------------------
bool rpc_server_t::get_broken_connection(void)
{
  return get_debugger_instance()->broken_connection;
}

//--------------------------------------------------------------------------
void rpc_server_t::set_broken_connection(void)
{
  get_debugger_instance()->broken_connection = true;
}

//-------------------------------------------------------------------------
int rpc_server_t::kill_process(void)
{
  const int NSEC = 5;
  dbg_mod->dbg_exit_process();

  // now, wait up to NSEC seconds until the process is gone
  qtime64_t wait_start = qtime64();
  qtime64_t wait_threshold = make_qtime64(
          get_secs(wait_start) + NSEC,
          get_usecs(wait_start));
  while ( qtime64() < wait_threshold )
  {
    gdecode_t result = dbg_mod->dbg_get_debug_event(&ev, 100);
    if ( result >= GDE_ONE_EVENT )
    {
      dbg_mod->dbg_continue_after_event(&ev);
      if ( ev.eid == PROCESS_EXIT )
        return 0;
    }
  }
  return NSEC;
}

//--------------------------------------------------------------------------
int debmod_t::send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty)
{
  rpc_server_t *s = (rpc_server_t *)rpc;
  return s->send_debug_names_to_ida(addrs, names, qty);
}

//--------------------------------------------------------------------------
int debmod_t::send_debug_event_to_ida(const debug_event_t *ev, int rqflags)
{
  rpc_server_t *s = (rpc_server_t *)rpc;
  return s->send_debug_event_to_ida(ev, rqflags);
}
