#ifndef __RPC_SERVER__
#define __RPC_SERVER__

#define VERBOSE_ENABLED
#include "rpc_engine.h"


// Note: the rpc_server_t implementation will consider all
// IOCTL IDs >= 0x01000000 as being server IOCTLs, and those will
// consequently *not* be passed to the debugger module.

class rpc_server_t: public rpc_engine_t
{
public:
  rpc_server_t(idarpc_stream_t *_irs)
    : rpc_engine_t(_irs),
      dbg_mod(NULL)
  {
    memset(&ev, 0, sizeof(ev));
    clear_channels(); //lint -esym(1566,rpc_server_t::channels) not inited
    struct ida_local lambda_t
    {
      static int ioctl(rpc_engine_t *rpc, int fn, const void *buf, size_t size, void **out, ssize_t *outsz)
      {
        rpc_server_t *serv = (rpc_server_t *) rpc;
        if ( fn >= 0x01000000 )
          return serv->handle_server_ioctl(fn, buf, size, out, outsz);
        else
          return serv->get_debugger_instance()->handle_ioctl(fn, buf, size, out, outsz);
      }
    };
    set_ioctl_handler(lambda_t::ioctl);
  }
  virtual ~rpc_server_t();
private:
  debug_event_t ev;
  debug_event_t pending_event;
  debmod_t *dbg_mod;
  FILE *channels[16];
  rpc_server_t &operator =(const rpc_server_t &);
  rpc_server_t(const rpc_server_t &);
  void append_start_or_attach(bytevec_t &req, int result) const;
protected:
  void close_all_channels();
  void clear_channels();
  int find_free_channel() const;

  int rpc_update_lowcnds(const uchar *ptr, const uchar *end);
  int rpc_update_bpts(const uchar *ptr, const uchar *end, bytevec_t &cmd);
  int rpc_attach_process(const uchar *ptr, const uchar *end);
  bool check_broken_connection(pid_t pid);
  virtual int handle_server_ioctl(int fn, const void *buf, size_t size, void **out, ssize_t *outsz);
public:
  void set_debugger_instance(debmod_t *instance);
  debmod_t *get_debugger_instance();
  void prepare_broken_connection();
  bool rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name);
  int send_debug_names_to_ida(ea_t *ea, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  virtual bytevec_t perform_request(const rpc_packet_t *rp);
  virtual int poll_events(int timeout_ms);
  virtual bool get_broken_connection(void);
  virtual void set_broken_connection(void);
};

//--------------------------------------------------------------------------
#ifdef __SINGLE_THREADED_SERVER__
typedef std::map<rpc_server_t *, bool> rpc_server_list_t;
#else
typedef std::map<rpc_server_t *, qthread_t> rpc_server_list_t;
#endif

// defined only in the single threaded version of the server:
extern rpc_server_t *g_global_server;

#endif
