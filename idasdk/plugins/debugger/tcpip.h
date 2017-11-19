#ifndef __TCPIP__
#define __TCPIP__

#include <pro.h>
#include <err.h>
#include <pronet.h>

#ifdef __NT__
#  define get_network_error()      WSAGetLastError()
#  define SYSTEM_SPECIFIC_ERRNO    GetLastError()
#  define SYSTEM_SPECIFIC_ERRSTR   winerr
#  define SET_SYSTEM_SPECIFIC_ERRNO(x) SetLastError(x)
#  define SYSTEM_SPECIFIC_TIMEOUT_ERROR WAIT_TIMEOUT
#else   // not NT, i.e. UNIX
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  define get_network_error()      errno
#  define closesocket(s)           close(s)
#  define SOCKET size_t
#  define INVALID_SOCKET size_t(-1)
#  define SOCKET_ERROR   (-1)
#  define SYSTEM_SPECIFIC_ERRNO   errno
#  define SYSTEM_SPECIFIC_ERRSTR  strerror
#  define SET_SYSTEM_SPECIFIC_ERRNO(x) errno=(x)
#  define SYSTEM_SPECIFIC_TIMEOUT_ERROR ETIME
#endif

#include "consts.h"

idarpc_stream_t *init_client_irs(const char *hostname, int port_number);
bool name_to_sockaddr(const char *name, ushort port, sockaddr_in *sa);
void term_client_irs(idarpc_stream_t *irs);
void term_server_irs(idarpc_stream_t *irs);
void setup_irs(idarpc_stream_t *irs);
int irs_ready(idarpc_stream_t *irs, int timeout_ms);
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n, int timeout);
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n);
void irs_term(idarpc_stream_t *irs);
bool init_irs_layer(void);
void NT_CDECL term_sockets(void);
int irs_error(idarpc_stream_t *);
bool irs_peername(idarpc_stream_t *irs, char *buf, size_t bufsize, bool lookupname = true);
bool irs_getname(idarpc_stream_t *irs, char *buf, size_t bufsize, bool lookupname = true);

#endif
