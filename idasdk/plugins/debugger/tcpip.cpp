#ifdef _WIN32
#define WINVER 0x0501  /* needed for ipv6 bits */
#include <winsock2.h>
#include <Ws2tcpip.h>
#ifndef UNDER_CE
#pragma warning(disable: 4191) // disable warnings about casts to FARPROC
#include <Wspiapi.h>           // use this header for Win2k compatibility (getnameinfo)
#endif
#endif

#include "tcpip.h"
#include <kernwin.hpp>

static void neterr(const char *module)
{
  int code = get_network_error();
  error("%s: %s", module, winerr(code));
}

//-------------------------------------------------------------------------
#if defined(__NT__)
void NT_CDECL term_sockets(void)
{
  WSACleanup();
}

//-------------------------------------------------------------------------
bool init_irs_layer(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD( 2, 0 );

  err = WSAStartup( wVersionRequested, &wsaData );
  if ( err != 0 )
    return false;

  atexit(term_sockets);

  /* Confirm that the WinSock DLL supports 2.0.*/
  /* Note that if the DLL supports versions greater    */
  /* than 2.0 in addition to 2.0, it will still return */
  /* 2.0 in wVersion since that is the version we      */
  /* requested.                                        */

  if ( LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 0 )
  {
    /* Tell the user that we couldn't find a usable */
    /* WinSock DLL.                                  */
    return false;
  }

  /* The WinSock DLL is acceptable. Proceed. */
  return true;
}
#else
#include <signal.h>
//-------------------------------------------------------------------------
void term_sockets(void)
{
}

//-------------------------------------------------------------------------
bool init_irs_layer(void)
{
#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif
  return true;
}
#endif

//-------------------------------------------------------------------------
static inline SOCKET sock_from_irs(idarpc_stream_t *irs)
{
  return (SOCKET)irs;
}

//-------------------------------------------------------------------------
void irs_term(idarpc_stream_t *irs)
{
  closesocket(sock_from_irs(irs));
  term_sockets();
}

//-------------------------------------------------------------------------
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n)
{
  return qsend(sock_from_irs(irs), buf, (int)n);
}

//-------------------------------------------------------------------------
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n, int timeout)
{
  if ( timeout != -1 && !irs_ready(irs, timeout) )
  {
    SET_SYSTEM_SPECIFIC_ERRNO(SYSTEM_SPECIFIC_TIMEOUT_ERROR);
    return -1; // no data
  }
  return qrecv(sock_from_irs(irs), buf, (int)n);
}

//-------------------------------------------------------------------------
int irs_error(idarpc_stream_t *)
{
  return get_network_error();
}

//-------------------------------------------------------------------------
int irs_ready(idarpc_stream_t *irs, int timeout)
{
  SOCKET s = sock_from_irs(irs);
  int milliseconds = timeout;
  int seconds = milliseconds / 1000;
  milliseconds %= 1000;
  struct timeval tv = { seconds, milliseconds * 1000 };
  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(s, &rd);
  return qselect(int(s+1), &rd, NULL, NULL, seconds != -1 ? &tv : NULL);
}

//--------------------------------------------------------------------------
void setup_irs(idarpc_stream_t *irs)
{
  SOCKET sock = sock_from_irs(irs);
  /* Set socket options.  We try to make the port reusable and have it
     close as fast as possible without waiting in unnecessary wait states
     on close.
   */
  int on = 1;
  char *const ptr = (char *)&on;
  if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, ptr, sizeof(on)) != 0 )
    neterr("setsockopt1");

  /* Enable TCP keep alive process. */
  if ( setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, ptr, sizeof(on)) != 0 )
    neterr("setsockopt2");

  /* Speed up the interactive response. */
  if ( setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, ptr, sizeof(on)) != 0 )
    neterr("setsockopt3");
}

//-------------------------------------------------------------------------
void term_server_irs(idarpc_stream_t *irs)
{
  closesocket(sock_from_irs(irs));
}

//-------------------------------------------------------------------------
void term_client_irs(idarpc_stream_t *irs)
{
  term_server_irs(irs);
  term_sockets();
}

//-------------------------------------------------------------------------
bool name_to_sockaddr(const char *name, ushort port, sockaddr_in *sa)
{
  memset(sa, 0, sizeof(sockaddr_in));
  return qhost2addr(sa, name, port);
}

//-------------------------------------------------------------------------
idarpc_stream_t *init_client_irs(const char *hostname, int port_number)
{
  if ( hostname[0] == '\0' )
  {
    warning("AUTOHIDE NONE\n"
            "Please specify the hostname in Debugger, Process options");
    return NULL;
  }

  if ( !init_irs_layer() )
  {
    warning("AUTOHIDE NONE\n"
            "Could not initialize sockets: %s", winerr(get_network_error()));
    return NULL;
  }

  struct addrinfo ai, *res, *e;
  char port[33];

  // try to enumerate all possible addresses
  memset(&ai,0, sizeof(ai));
  ai.ai_flags = AI_CANONNAME;
  ai.ai_family = PF_UNSPEC;
  ai.ai_socktype = SOCK_STREAM;
  qsnprintf(port, sizeof(port), "%d", port_number);

  bool ok = false;
  char errstr[MAXSTR];
  errstr[0] = '\0';
  SOCKET sock = INVALID_SOCKET;
  int code = getaddrinfo(hostname, port, &ai, &res);
  if ( code != 0 )
  { // failed to resolve the name
#ifdef UNDER_CE
    wchar16_t *werrstr = gai_strerror(code);
    qstring utf8;
    utf16_utf8(&utf8, werrstr);
    qstrncpy(errstr, utf8.c_str(), sizeof(errstr));
#else
    qstrncpy(errstr, gai_strerror(code), sizeof(errstr));
#endif
  }
  else
  {
    for ( e = res; !ok && e != NULL; e = e->ai_next )
    {
      char uaddr[INET6_ADDRSTRLEN+1];
      char uport[33];
      if ( getnameinfo(e->ai_addr, e->ai_addrlen, uaddr, sizeof(uaddr),
                       uport, sizeof(uport), NI_NUMERICHOST | NI_NUMERICSERV) != 0 )
      {
        code = get_network_error();
NETERR:
        qstrncpy(errstr, winerr(code), sizeof(errstr));
        continue;
      }
      sock = socket(e->ai_family, e->ai_socktype, e->ai_protocol);
      if ( sock == INVALID_SOCKET )
      {
        code = get_network_error();
        goto NETERR;
      }
      setup_irs((idarpc_stream_t*)sock);

      if ( connect(sock, e->ai_addr, e->ai_addrlen) == SOCKET_ERROR )
      {
        code = get_network_error();
        closesocket(sock);
        goto NETERR;
      }
      ok = true;
    }
    freeaddrinfo(res);
  }
  if ( !ok )
  {
    msg("Could not connect to %s:%d: %s\n", hostname, port_number, errstr);
    return NULL;
  }

  return (idarpc_stream_t*)sock;
}

//-------------------------------------------------------------------------
static bool sockaddr_to_name(
        const struct sockaddr *addr,
        socklen_t len,
        char *buf,
        size_t bufsize,
        bool lookupname)
{
  char *ptr = buf;
  char *end = buf + bufsize;
  // get dns name
  if ( lookupname && getnameinfo(addr, len,
                   ptr, end-ptr,
                   NULL, 0,
                   NI_NAMEREQD) == 0 )
  {
    ptr = tail(ptr);
    APPCHAR(ptr, end, '(');
  }
  // get ip address
  if ( getnameinfo(addr, len,
                   ptr, end-ptr,
                   NULL, 0,
                   NI_NUMERICHOST) == 0 )
  {
    bool app = ptr > buf;
    ptr = tail(ptr);
    if ( app )
      APPEND(ptr, end, ")");
  }
  else
  {
    if ( ptr > buf )
      *--ptr = '\0';
  }
  return ptr > buf;
}

//-------------------------------------------------------------------------
bool irs_peername(idarpc_stream_t *irs, char *buf, size_t bufsize, bool lookupname)
{
  struct sockaddr addr;
  socklen_t len = sizeof(addr);
  if ( getpeername(sock_from_irs(irs), &addr, &len) != 0 )
    return false;

  return sockaddr_to_name(&addr, len, buf, bufsize, lookupname);
}

//-------------------------------------------------------------------------
bool irs_getname(idarpc_stream_t *irs, char *buf, size_t bufsize, bool lookupname)
{
  struct sockaddr addr;
  socklen_t len = sizeof(addr);
  if ( getsockname(sock_from_irs(irs), &addr, &len) != 0 )
    return false;

  return sockaddr_to_name(&addr, len, buf, bufsize, lookupname);
}
