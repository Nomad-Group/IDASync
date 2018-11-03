#ifndef __RPC_SERVER_IOCTLS__
#define __RPC_SERVER_IOCTLS__

// Those start at 0x01000000. See note in rpc_server.h

#define DWARF_RPCSRV_IOCTL_OK 0
#define DWARF_RPCSRV_IOCTL_ERROR -1

enum rpcsrv_ioctl_t
{
  // Get DWARF sections information.
  //
  // client->server
  //   (unpacked) char *         : file_path (on the server's disk.)
  //   (packed)   uint32         : processor ID (as in: ph.id)
  // server->client
  //   (unpacked) byte           : DWARF info found
  //   (packed)   uint32         : is_64 (0 - no, !=0 - yes)
  //   (packed)   uint32         : is_msb (0 - no, !=0 - yes)
  //   (packed)   uint64         : declared load address
  //   (packed)   uint32         : number of DWARF section infos.
  //   (packed)   sec info       : DWARF section info, N times.
  // Returns: 0   - ok
  //          !=0 - error (text in output buffer.)
  //
  // The structure of a "sec info" is:
  //   (packed)   uint64 address_in_memory
  //   (packed)   uint64 size (in bytes)
  //   (packed)   uint16 section_index
  //   (unpacked) char * section_name
  rpcsrv_ioctl_dwarf_secinfo = 0x01000000 + 1,

  // Get DWARF section data.
  //
  // client->server
  //   (unpacked) char *         : file_path (on the server's disk.)
  //   (packed)   uint32         : processor ID (as in: ph.id)
  //   (packed)   uint16         : DWARF section index (as returned by 'rpcsrv_ioctl_dwarf_secinfo')
  // server->client
  //   (unpacked) byte *         : DWARF section data.
  // Returns: 0   - ok
  //          !=0 - error
  rpcsrv_ioctl_dwarf_secdata,
};

#endif // __RPC_SERVER_IOCTLS__
