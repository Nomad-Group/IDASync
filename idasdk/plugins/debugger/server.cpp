/*
       IDA remote debugger server
*/

#include "server.h"

// Provide dummy versions for tinfo copy/clear. Debugger servers do not use them
#if !defined(__NT__) || defined(UNDER_CE) // defined(__ANDROID__) || defined(__ARMLINUX__) || defined(UNDER_CE)
idaman void ida_export copy_tinfo_t(tinfo_t *, const tinfo_t &) {}
idaman void ida_export clear_tinfo_t(tinfo_t *) {}
#endif
//lint -esym(714, dump_udt) not referenced
void dump_udt(const char *, const struct udt_type_data_t &) {}


//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
static const char *server_password = NULL;
static const char *ipv4_address = NULL;
static bool verbose = false;
static bool keep_broken_connections = false;

#ifdef __SINGLE_THREADED_SERVER__

static bool init_lock(void) { return true; }
bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }

static inline bool srv_lock_init(void) { return true; }
bool srv_lock_begin(void) { return true; }
bool srv_lock_end(void) { return true; }
static inline bool srv_lock_free(void) { return true; }

#else

static qmutex_t g_mutex = NULL;

//--------------------------------------------------------------------------
static bool init_lock(void)
{
  g_mutex = qmutex_create();
  return g_mutex != NULL;
}

//--------------------------------------------------------------------------
bool lock_begin(void)
{
  return qmutex_lock(g_mutex);
}

//--------------------------------------------------------------------------
bool lock_end(void)
{
  return qmutex_unlock(g_mutex);
}

//--------------------------------------------------------------------------
qmutex_t g_lock = NULL;

//--------------------------------------------------------------------------
static inline bool srv_lock_init(void)
{
  g_lock = qmutex_create();
  return g_lock != NULL;
}

//--------------------------------------------------------------------------
bool srv_lock_begin(void)
{
  return qmutex_lock(g_lock);
}

//--------------------------------------------------------------------------
bool srv_lock_end(void)
{
  return qmutex_unlock(g_lock);
}

//--------------------------------------------------------------------------
static inline bool srv_lock_free(void)
{
  return qmutex_free(g_lock);
}

#endif

//--------------------------------------------------------------------------
rpc_server_list_t clients_list;
rpc_server_t *g_global_server = NULL;

//--------------------------------------------------------------------------
// perform an action (func) on all debuggers
int for_all_debuggers(debmod_visitor_t &v)
{
  int code = 0;
  srv_lock_begin();
  {
    rpc_server_list_t::iterator it;
    for ( it=clients_list.begin(); it != clients_list.end(); ++it )
    {
      code = v.visit(it->first->get_debugger_instance());
      if ( code != 0 )
        break;
    }
  } srv_lock_end();
  return code;
}

#ifndef USE_ASYNC

//--------------------------------------------------------------------------
void neterr(idarpc_stream_t *irs, const char *module)
{
  int code = irs_error(irs);
  qeprintf("%s: %s\n", module, winerr(code));
  exit(1);
}

static SOCKET listen_socket = INVALID_SOCKET;
#endif

#ifndef UNDER_CE

// Set this variable before generating SIGINT for internal purposes
bool ignore_sigint = false;

//--------------------------------------------------------------------------
static void NT_CDECL shutdown_gracefully(int signum)
{
  if ( signum == SIGINT && ignore_sigint )
  {
    ignore_sigint = false;
    return;
  }

#if defined(__NT__) || defined(__ARM__) // strsignal() is not available
  qeprintf("got signal #%d, terminating\n", signum);
#else
  qeprintf("%s: terminating the server\n", strsignal(signum));
#endif

  srv_lock_begin();

  for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
  {
    rpc_server_t *server = it->first;
#ifndef __SINGLE_THREADED_SERVER__
    qthread_t thr = it->second;

    // free thread
    if ( thr != NULL )
      qthread_free(thr);
#endif
    if ( server == NULL || server->irs == NULL )
      continue;

    debmod_t *d = server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process(); // kill the process instead of letting it run in wild

    server->term_irs();
  }

  clients_list.clear();
  srv_lock_end();
  srv_lock_free();

  if ( listen_socket != INVALID_SOCKET )
    closesocket(listen_socket);

  term_subsystem();
  _exit(1);
}
#endif

//--------------------------------------------------------------------------
static void handle_single_session(rpc_server_t *server)
{
  static int s_sess_id = 1;
  int sid = s_sess_id++;

  char peername[MAXSTR];
  if ( !irs_peername(server->irs, peername, sizeof(peername), false) )
    qstrncpy(peername, "(unknown)", sizeof(peername));
  lprintf("=========================================================\n"
          "[%d] Accepting connection from %s...\n", sid, peername);

  bytevec_t req = prepare_rpc_packet(RPC_OPEN);
  append_dd(req, IDD_INTERFACE_VERSION);
  append_dd(req, DEBUGGER_ID);
  append_dd(req, sizeof(ea_t));

  rpc_packet_t *rp = server->process_request(req, true);

  bool handle_request = true;
  bool send_response  = true;
  bool ok;
  if ( rp == NULL )
  {
    lprintf("[%d] Could not establish the connection\n", sid);
    handle_request = false;
    send_response  = false;
  }

  if ( handle_request )
  {
    // Answer is beyond the rpc_packet_t buffer
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;

    ok = extract_long(&answer, end) != 0;
    if ( !ok )
    {
      lprintf("[%d] Incompatible IDA version\n", sid);
      send_response = false;
    }
    else if ( server_password != NULL )
    {
      char *pass = extract_str(&answer, end);
      if ( strcmp(pass, server_password) != '\0' )
      {
        lprintf("[%d] Bad password\n", sid);
        ok = false;
      }
    }

    qfree(rp);
  }

  if ( send_response )
  {
    req = prepare_rpc_packet(RPC_OK);
    append_dd(req, ok);
    server->send_request(req);

    if ( ok )
    {
      // the main loop: handle client requests until it drops the connection
      // or sends us RPC_OK (see rpc_debmod_t::close_remote)
      bytevec_t empty;
      rpc_packet_t *packet = server->process_request(empty);
      if ( packet != NULL )
        qfree(packet);
    }
  }
  server->network_error_code = 0;
  lprintf("[%d] Closing connection from %s...\n", sid, peername);

  bool preserve_server = keep_broken_connections && server->get_broken_connection();
  if ( !preserve_server )
  { // Terminate dedicated debugger instance.
    server->get_debugger_instance()->dbg_term();
    server->term_irs();
  }
  else
  {
    server->term_irs();
    lprintf("[%d] Debugged session entered into sleeping mode\n", sid);
    server->prepare_broken_connection();
  }

  if ( !preserve_server )
  {
    // Remove the session from the list
    srv_lock_begin();
    for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
    {
      if ( it->first != server )
        continue;

#ifndef __SINGLE_THREADED_SERVER__
      // free the thread resources
      qthread_free(it->second);
#endif

      // remove client from the list
      clients_list.erase(it);
      break;
    }
    srv_lock_end();

    // Free the debug session
    delete server;
  }
}

//--------------------------------------------------------------------------
int idaapi thread_handle_session(void *ctx)
{
  rpc_server_t *server = (rpc_server_t *)ctx;
  handle_single_session(server);
  return 0;
}

//--------------------------------------------------------------------------
void handle_session(rpc_server_t *server)
{
#ifndef __SINGLE_THREADED_SERVER__
  qthread_t t = qthread_create(thread_handle_session, (void *)server);
  bool run_handler = false;
#else
  bool t = true;
  bool run_handler = true;
#endif

  // Add the session to the list
  srv_lock_begin();
  clients_list[server] = t;
  g_global_server = server;
  srv_lock_end();

  if ( run_handler )
    handle_single_session(server);
}

#ifdef UNDER_CE
//--------------------------------------------------------------------------
extern "C"
{
  BOOL WINAPI SetKMode(BOOL fMode);
  DWORD WINAPI SetProcPermissions(DWORD newperms);
};

class get_permissions_t
{
  DWORD dwPerm;
  BOOL bMode;
public:
  get_permissions_t(void)
  {
    bMode = SetKMode(TRUE); // Switch to kernel mode
    dwPerm = SetProcPermissions(0xFFFFFFFF); // Set access rights to the whole system
  }
  ~get_permissions_t(void)
  {
    SetProcPermissions(dwPerm);
    SetKMode(bMode);
  }
};
#endif

//--------------------------------------------------------------------------
// For ActiveSync transport, we create a DLL
// This DLL should never exit(), of course, but just close the connection
#ifdef USE_ASYNC

#include "rapi/rapi.h"

static bool in_use = false;
static uchar *ptr;

//--------------------------------------------------------------------------
static int display_exception(int code, EXCEPTION_POINTERS *ep)
{
  /*
  CONTEXT &ctx = *(ep->ContextRecord);
  EXCEPTION_RECORD &er = *(ep->ExceptionRecord);
  char name[MAXSTR];
  get_exception_name(er.ExceptionCode, name, sizeof(name));
  // find our imagebase
  ptr = (uchar*)(size_t(ptr) & ~0xFFF); // point to the beginning of a page
  while ( !IsBadReadPtr(ptr, 2) )
    ptr -= 0x1000;

  msg("%08lX: debugger server %s (BASE %08lX)\n", ctx.Pc-(uint32)ptr, name, ptr);

  DEBUG_CONTEXT(ctx);
  //  show_exception_record(er);
  */
  return EXCEPTION_EXECUTE_HANDLER;
  //  return EXCEPTION_CONTINUE_SEARCH;
}

//--------------------------------------------------------------------------
static DWORD calc_our_crc32(const char *fname)
{
  linput_t *li = open_linput(fname, false);
  DWORD crc32 = calc_file_crc32(li);
  close_linput(li);
  return crc32;
}

//--------------------------------------------------------------------------
// __try handler can't be placed in fuction which requires object unwinding
static void protected_privileged_session(IRAPIStream* pStream)
{
  try
  {
    idarpc_stream_t *irs = init_server_irs(pStream);
    if ( irs == NULL )
      return;

    rpc_server_t *server = new rpc_server_t(irs);
    server->verbose = verbose;
    server->set_debugger_instance(create_debug_session());

    static bool inited = false;
    if ( !inited )
    {
      inited = true;
      init_idc();
    }
    handle_session(server);
  }
  //__except ( display_exception(GetExceptionCode(), GetExceptionInformation()) )
  catch(...)
  {
  }
}

//--------------------------------------------------------------------------
extern "C" __declspec(dllexport)
int ida_server(DWORD dwInput, BYTE* pInput,
               DWORD* pcbOutput, BYTE** ppOutput,
               IRAPIStream* pStream)
{
  lprintf("IDA " SYSTEM SYSBITS " remote debug server v1.%d.\n"
    "Copyright Hex-Rays 2004-2015\n", IDD_INTERFACE_VERSION);

  // Call the debugger module to initialize its subsystem once
  if ( !init_subsystem() )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  // check our crc32
  DWORD crc32 = calc_our_crc32((char *)pInput);
  DWORD dummy = 0;
  pStream->Write(&crc32, sizeof(crc32), &dummy);
  if ( dummy != sizeof(crc32) )
  {
ERR:
    pStream->Release();
    //    lprintf("Debugger server checksum mismatch - shutting down\n");
    return ERROR_CRC;
  }
  DWORD ok;
  dummy = 0;
  pStream->Read(&ok, sizeof(ok), &dummy);
  if ( dummy != sizeof(ok) || ok != 1 )
    goto ERR;

  // only one instance is allowed
  if ( in_use )
  {
    static const char busy[] = "BUSY";
    pStream->Write(busy, sizeof(busy)-1, &dummy);
    pStream->Release();
    return ERROR_BUSY;
  }
  in_use = true;

  ptr = (uchar*)ida_server;
  {
    get_permissions_t all_permissions;
    protected_privileged_session(pStream);
  }

  in_use = false;
  return 0;
}

#else

//--------------------------------------------------------------------------
bool are_broken_connections_supported(void)
{
  return debmod_t::reuse_broken_connections;
}

//--------------------------------------------------------------------------
// debugger remote server - TCP/IP mode
int NT_CDECL main(int argc, char *argv[])
{
#ifdef ENABLE_LOWCNDS
  init_idc();
#endif

  // call the debugger module to initialize its subsystem once
  if ( !init_lock()
    || !init_subsystem()
#ifndef __SINGLE_THREADED_SERVER__
    || !srv_lock_init()
#endif
    )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  bool reuse_conns = are_broken_connections_supported();
  int port_number = DEBUGGER_PORT_NUMBER;
  lprintf("IDA " SYSTEM SYSBITS " remote debug server(" __SERVER_TYPE__ ") v1.%d. Hex-Rays (c) 2004-2015\n", IDD_INTERFACE_VERSION);
  while ( argc > 1 && (argv[1][0] == '-' || argv[1][0] == '/'))
  {
    switch ( argv[1][1] )
    {
    case 'p':
      port_number = atoi(&argv[1][2]);
      break;
    case 'P':
      server_password = argv[1] + 2;
      break;
    case 'i':
      ipv4_address = argv[1] + 2;
      break;
    case 'v':
      verbose = true;
      break;
    case 'k':
      if ( !reuse_conns )
        error("Sorry, debugger doesn't support reusing broken connections\n");
      keep_broken_connections = true;
      break;
    default:
      error("usage: ida_remote [switches]\n"
               "  -i...  IP address to bind to (default to any)\n"
               "  -v     verbose\n"
               "  -p...  port number\n"
               "  -P...  password\n"
               "%s", reuse_conns ? "  -k     keep broken connections\n" : "");
      break;
    }
    argv++;
    argc--;
  }

#ifndef UNDER_CE
#ifndef __NT__
  signal(SIGHUP, shutdown_gracefully);
#endif
  signal(SIGINT, shutdown_gracefully);
  signal(SIGTERM, shutdown_gracefully);
  signal(SIGSEGV, shutdown_gracefully);
  //  signal(SIGPIPE, SIG_IGN);
#endif

  if ( !init_irs_layer() )
  {
    neterr(NULL, "init_sockets");
  }

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);
  if ( listen_socket == INVALID_SOCKET )
    neterr(NULL, "socket");

  idarpc_stream_t *irs = (idarpc_stream_t *)listen_socket;
  setup_irs(irs);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = qhtons(short(port_number));
  if ( ipv4_address != NULL )
    sa.sin_addr.s_addr = inet_addr(ipv4_address);
  if( sa.sin_addr.s_addr == INADDR_NONE )
  {
    lprintf("Cannot parse IP v4 address %s, falling back to INADDR_ANY\n", ipv4_address);
    sa.sin_addr.s_addr = INADDR_ANY;
    ipv4_address = NULL;
  }

  if ( bind(listen_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
    neterr(irs, "bind");

  if ( listen(listen_socket, SOMAXCONN) == SOCKET_ERROR )
    neterr(irs, "listen");

  hostent *local_host = gethostbyname("");
  if ( local_host != NULL )
  {
    const char *local_ip;
    if ( ipv4_address != NULL )
      local_ip = ipv4_address;
    else
      local_ip = inet_ntoa(*(struct in_addr *)*local_host->h_addr_list);
    if ( local_host->h_name != NULL && local_ip != NULL )
      lprintf("Host %s (%s): ", local_host->h_name, local_ip);
    else if ( local_ip != NULL )
      lprintf("Host %s: ", local_ip);
  }
  lprintf("Listening on port #%u...\n", port_number);

  while ( true )
  {
    socklen_t salen = sizeof(sa);
    // try to set CLOEXEC bit as soon as possible on Linux
#if defined(__LINUX__) && !defined(__ARM__)
    SOCKET rpc_socket = accept4(listen_socket, (sockaddr *)&sa, &salen, SOCK_CLOEXEC);
#else
    SOCKET rpc_socket = accept(listen_socket, (sockaddr *)&sa, &salen);
#endif
    if ( rpc_socket == INVALID_SOCKET )
    {
#ifdef UNDER_CE
      if ( WSAGetLastError() != WSAEINTR )
#else
      if ( errno != EINTR )
#endif
        neterr(irs, "accept");
      continue;
    }
#if defined(__LINUX__) && defined(LIBWRAP)
    const char *p = check_connection(rpc_socket);
    if ( p != NULL )
    {
      fprintf(stderr,
        "ida-server CONNECTION REFUSED from %s (tcp_wrappers)\n", p);
      shutdown(rpc_socket, 2);
      close(rpc_socket);
      continue;
    }
#endif // defined(__LINUX__) && defined(LIBWRAP)

    // Only Linux has accept4(), so we have to set CLOEXEC now for other Unixes
#if defined(__MAC__) || defined(__LINUX__) && defined(__ARM__)
    fcntl(rpc_socket, F_SETFD, FD_CLOEXEC);
#endif

    rpc_server_t *server = new rpc_server_t((idarpc_stream_t *)rpc_socket);
    server->verbose = verbose;
    server->set_debugger_instance(create_debug_session());
    {
#ifdef UNDER_CE
      get_permissions_t all_permissions;
#endif
      handle_session(server);
    }
  }
/* NOTREACHED
  term_lock();
  term_subsystem();
#ifndef __SINGLE_THREADED_SERVER__
  qmutex_free(g_lock);
#endif
*/
}

#endif
