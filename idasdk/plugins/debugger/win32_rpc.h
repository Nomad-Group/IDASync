
#ifndef WIN32_RPC_H
#define WIN32_RPC_H

// IOCTL codes for the win32 debugger

#define WIN32_IOCTL_RDMSR    0 // read model specific register
#define WIN32_IOCTL_WRMSR    1 // write model specific register
#define WIN32_IOCTL_READFILE 2 // server->client: read bytes from the input file
                               //  uint64 offset;
                               //  uint32 length;
                               // returns: 1 - ok
                               //         -2 - error (text in output buffer)

// Open file for PDB retrieval.
//
// This operation will *typically* require that executable data
// be provided to the underlying MS PDB "DIA" dll. Therefore,
// there is _no_ way (currently) that this operation will
// immediately return something relevant. The client must
// poll for _OPERATION_COMPLETE-ness.
//
// client->server
//   (unpacked) compiler_info_t: compiler_info
//   (packed)   uint64         : base_address
//   (unpacked) char *         : input_file
//   (unpacked) char *         : user symbols path
// server->client
//   (packed)   uint64         : session handle
#define WIN32_IOCTL_PDB_OPEN               3

// Close PDB 'session', previously opened with _PDB_OPEN.
//
// client->server
//   (unpacked) uint64         : session handle
// server->client
//   void
#define WIN32_IOCTL_PDB_CLOSE              4

// Fetch the data for one symbol.
//
// Synchronous operation.
//
// client->server
//   (unpacked) uint64         : session handle
//   (packed)   uint64         : symbol ID
// server->client
//       (unpacked) uint32: The integer value 1.
//       (serialized) data: Packed symbol data (once).
#define WIN32_IOCTL_PDB_FETCH_SYMBOL       5

// Fetch the data for the children of a symbol.
//
// Synchronous operation.
//
// client->server
//   (unpacked) uint64         : session handle
//   (packed)   uint64         : symbol ID
//   (packed)   uint32         : children type (a SymTagEnum)
// server->client
//       (unpacked) uint32: Number of symbols whose data
//                          has been fetched.
//       (serialized) data: Packed symbol data (N times).
#define WIN32_IOCTL_PDB_FETCH_CHILDREN     6

// Is the current operation complete?
//
// Depending on the type of the operation, the contents
// of the results will differ:
//  - _OPEN
//       (packed) uint64 : Global symbol ID.
//       (packed) uint32 : machine type.
//       (packed) uint32 : DIA version.
//
// NOTE: Currently, this IOCTL only makes sense to check
//       for completeness of operation _OPEN, but this
//       might change in the future.
//
// client->server
//   (unpacked) uint64         : session handle
// server->client
//   (unpacked) byte[]         : operation result data.
#define WIN32_IOCTL_PDB_OPERATION_COMPLETE 7

enum ioctl_pdb_code_t
{
  pdb_ok = 1,
  pdb_error = -2,

  // Fetch-specific
  pdb_operation_complete   = pdb_ok,
  pdb_operation_incomplete = -10,
};


// WIN32_IOCTL_WRMSR uses this structure:
struct win32_wrmsr_t
{
  uint32 reg;
  uint64 value;
};


#endif // WIN32_RPC_H
