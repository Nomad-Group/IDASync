/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2015 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDD_HPP
#define _IDD_HPP
#include <range.hpp>
#include <ua.hpp>

//-V:debug_event_t:730 not all members of a class are initialized inside the constructor

/*! \file idd.hpp

  \brief Contains definition of the interface to IDD modules.

  The interface consists of structures describing the target
  debugged processor and a debugging API.
*/

/// The IDD interface version number
#define         IDD_INTERFACE_VERSION   22

class idc_value_t;
class tinfo_t;
/// \cond
typedef uchar type_t;
typedef uchar p_list;
/// \endcond

//====================================================================
//
//                       Process and Threads
//

typedef int pid_t;                   ///< process id
typedef int thid_t;                  ///< thread id

#define NO_PROCESS pid_t(0xFFFFFFFF) ///< No process
#define NO_THREAD  0                 ///< No thread.
                                     ///< in ::PROCESS_START this value
                                     ///< can be used to specify that
                                     ///< the main thread has not been created.
                                     ///< It will be initialized later
                                     ///< by a ::THREAD_START event.

/// Process information
struct process_info_t
{
  pid_t pid;    ///< process id
  qstring name; ///< process name
};
DECLARE_TYPE_AS_MOVABLE(process_info_t);
typedef qvector<process_info_t> procinfo_vec_t;

//--------------------------------------------------------------------
/// Runtime attributes of the debugger/process.
/// It is guaranteed that these attributes are really valid after start/attach process
struct debapp_attrs_t
{
  int32 cbsize;         ///< control field: size of this structure

  /// address size of the process.
  /// Since 64-bit debuggers usually can debug 32-bit applications, we can not
  /// rely on sizeof(ea_t) to detect the current address size. The following
  /// variable should be used instead. It is initialized with 8 for 64-bit
  /// debuggers but they should adjust it as soon as they learn that a
  /// 32-bit application is being debugged.
  /// For 32-bit debuggers it is initialized with 4.
  int addrsize;

  qstring platform;     ///< platform name process is running/debugging under.
                        ///< (is used as a key value in exceptions.cfg)

/// \def{DEF_ADDRSIZE, Default address size - see debapp_attrs_t::addrsize}
#ifdef __EA64__
#define DEF_ADDRSIZE  8
#else
#define DEF_ADDRSIZE  4
#endif

  /// Constructor - initialize with #DEF_ADDRSIZE
  debapp_attrs_t(): cbsize(sizeof(debapp_attrs_t)), addrsize(DEF_ADDRSIZE) {}
};

//====================================================================
//
//                          Registers
//

typedef unsigned char register_class_t; ///< Each register is associated to
                                        ///< a register class.
                                        ///< example: "segment", "mmx", ...

/// Debuggee register information
struct register_info_t
{
  const char *name;                   ///< Register name.
  uint32 flags;                       ///< \ref REGISTER_
/// \defgroup REGISTER_ Register info attribute flags
/// Used by register_info_t::flags
//@{
#define REGISTER_READONLY 0x0001      ///< the user can't modify the current value of this register
#define REGISTER_IP       0x0002      ///< instruction pointer
#define REGISTER_SP       0x0004      ///< stack pointer
#define REGISTER_FP       0x0008      ///< frame pointer
#define REGISTER_ADDRESS  0x0010      ///< may contain an address
#define REGISTER_CS       0x0020      ///< code segment
#define REGISTER_SS       0x0040      ///< stack segment
#define REGISTER_NOLF     0x0080      ///< displays this register without returning to the next line
                                      ///< allowing the next register to be displayed to its right (on the same line)
#define REGISTER_CUSTFMT  0x0100      ///< register should be displayed using a custom data format.
                                      ///< the format name is in bit_strings[0]
                                      ///< the corresponding ::regval_t will use ::bytevec_t
//@}
  register_class_t register_class;    ///< segment, mmx, etc.
  op_dtype_t dtype;                   ///< Register size (see \ref dt_)
  const char *const *bit_strings;     ///< strings corresponding to each bit of the register.
                                      ///< (NULL = no bit, same name = multi-bits mask)
  uval_t default_bit_strings_mask;    ///< mask of default bits
};
DECLARE_TYPE_AS_MOVABLE(register_info_t);

//====================================================================
//
//                           Memory
//

/// Used by debugger modules to report memory are information to IDA kernel.
/// It is ok to return empty fields if information is not available.
struct memory_info_t : public range_t
{
  qstring name;                ///< Memory range name
  qstring sclass;              ///< Memory range class name
  ea_t sbase;                  ///< Segment base (meaningful only for segmented architectures, e.g. 16-bit x86)
                               ///< The base is specified in paragraphs (i.e. shifted to the right by 4)
  uchar bitness;               ///< Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
  uchar perm;                  ///< Memory range permissions (0-no information): see segment.hpp
  memory_info_t(void)
    : sbase(0),bitness(0),perm(0) {}
  bool operator ==(const memory_info_t &r) const
  {
    return start_ea == r.start_ea
        && end_ea   == r.end_ea
        && name    == r.name
        && sclass  == r.sclass
        && sbase   == r.sbase
        && bitness == r.bitness
        && perm    == r.perm;
  }
  bool operator !=(const memory_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(memory_info_t);
typedef qvector<memory_info_t> meminfo_vec_t; ///< vector of memory info objects

/// Used by debugger modules to keep track of images that are not mapped uniformly into memory.
struct scattered_segm_t : public range_t
{
  qstring name; ///< name of the segment
};
DECLARE_TYPE_AS_MOVABLE(scattered_segm_t);
typedef qvector<scattered_segm_t> scattered_image_t; ///< vector of scattered segments

//====================================================================
//
//                         Debug events
//

/// Debug event codes
enum event_id_t
{
  NO_EVENT       = 0x00000000, ///< Not an interesting event. This event can be
                               ///< used if the debugger module needs to return
                               ///< an event but there are no valid events.
  PROCESS_START  = 0x00000001, ///< New process has been started.
  PROCESS_EXIT   = 0x00000002, ///< Process has been stopped.
  THREAD_START   = 0x00000004, ///< New thread has been started.
  THREAD_EXIT    = 0x00000008, ///< Thread has been stopped.
  BREAKPOINT     = 0x00000010, ///< Breakpoint has been reached. IDA will complain
                               ///< about unknown breakpoints, they should be reported
                               ///< as exceptions.
  STEP           = 0x00000020, ///< One instruction has been executed. Spurious
                               ///< events of this kind are silently ignored by IDA.
  EXCEPTION      = 0x00000040, ///< Exception.
  LIBRARY_LOAD   = 0x00000080, ///< New library has been loaded.
  LIBRARY_UNLOAD = 0x00000100, ///< Library has been unloaded.
  INFORMATION    = 0x00000200, ///< User-defined information.
                               ///< This event can be used to return empty information
                               ///< This will cause IDA to call get_debug_event()
                               ///< immediately once more.
  SYSCALL        = 0x00000400, ///< Syscall (not used yet).
  WINMESSAGE     = 0x00000800, ///< Window message (not used yet).
  PROCESS_ATTACH = 0x00001000, ///< Successfully attached to running process.
  PROCESS_DETACH = 0x00002000, ///< Successfully detached from process.
  PROCESS_SUSPEND= 0x00004000, ///< Process has been suspended.
                               ///< This event can be used by the debugger module
                               ///< to signal if the process spontaneously gets
                               ///< suspended (not because of an exception,
                               ///< breakpoint, or single step). IDA will silently
                               ///< switch to the 'suspended process' mode without
                               ///< displaying any messages.
  TRACE_FULL     = 0x00008000, ///< The trace buffer of the tracer module is full
                               ///< and IDA needs to read it before continuing
};


/// Describes a module load event.
/// (see ::PROCESS_START, ::PROCESS_ATTACH, ::LIBRARY_LOAD)
struct module_info_t
{
  char name[MAXSTR];    ///< full name of the module
  ea_t base;            ///< module base address. if unknown pass #BADADDR
  asize_t size;         ///< module size. if unknown pass 0
  ea_t rebase_to;       ///< if not #BADADDR, then rebase the program to the specified address
};

/// Describes a breakpoint event.
/// (see ::BREAKPOINT)
struct e_breakpoint_t
{
  ea_t hea;             ///< Possible address referenced by hardware breakpoints
  ea_t kea;             ///< Address of the triggered bpt from the kernel's point
                        ///< of view. (for some systems with special memory mappings,
                        ///< the triggered ea might be different from event ea).
                        ///< Use to #BADADDR for flat memory model.
};

/// Describes an exception.
/// (see ::EXCEPTION)
struct e_exception_t
{
  uint32 code;          ///< Exception code
  bool can_cont;        ///< Execution of the process can continue after this exception?
  ea_t ea;              ///< Possible address referenced by the exception
  char info[MAXSTR];    ///< Exception message
};

/// This structure is used only when detailed information
///   about a debug event is needed.
struct debug_event_t
{
  debug_event_t(void) : eid(NO_EVENT) {}

  /// \name Note:
  /// The following fields must be filled for all events:
  //@{
  event_id_t eid;          ///< Event code (used to decipher 'info' union)
  pid_t pid;               ///< Process where the event occurred
  thid_t tid;              ///< Thread where the event occurred
  ea_t ea;                 ///< Address where the event occurred
  bool handled;            ///< Is event handled by the debugger?.
                           ///< (from the system's point of view)
                           ///< Meaningful for ::EXCEPTION events
  //@}
#ifndef SWIG
  union
  {
#endif //SWIG
    module_info_t modinfo; ///< ::PROCESS_START, ::PROCESS_ATTACH, ::LIBRARY_LOAD
    int exit_code;         ///< ::PROCESS_EXIT, ::THREAD_EXIT
    char info[MAXSTR];     ///< ::LIBRARY_UNLOAD (unloaded library name)
                           ///< ::INFORMATION (will be displayed in the
                           ///<              messages window if not empty)
    e_breakpoint_t bpt;    ///< ::BREAKPOINT
    e_exception_t exc;     ///< ::EXCEPTION
#ifndef SWIG
  };
#endif //SWIG
  /// On some systems with special memory mappings the triggered ea might be
  /// different from the actual ea. Calculate the address to use.
  ea_t bpt_ea(void) const
  {
    return eid == BREAKPOINT && bpt.kea != BADADDR ? bpt.kea : ea;
  }
};
DECLARE_TYPE_AS_MOVABLE(debug_event_t);

typedef int bpttype_t; ///< hardware breakpoint type (see \ref BPT_H)

/// \defgroup BPT_H Hardware breakpoint ids
/// Fire the breakpoint upon one of these events
//@{
const bpttype_t
  BPT_WRITE    = 1,                   ///< Write access
  BPT_READ     = 2,                   ///< Read access
  BPT_RDWR     = 3,                   ///< Read/write access
  BPT_SOFT     = 4,                   ///< Software breakpoint
  BPT_EXEC     = 8,                   ///< Execute instruction
  BPT_DEFAULT  = (BPT_SOFT|BPT_EXEC); ///< Choose bpt type automatically
//@}

/// Exception information
struct exception_info_t
{
  uint code;              ///< exception code
  uint32 flags;           ///< \ref EXC_
/// \defgroup EXC_ Exception info flags
/// Used by exception_info_t::flags
//@{
#define EXC_BREAK  0x0001 ///< break on the exception
#define EXC_HANDLE 0x0002 ///< should be handled by the debugger?
#define EXC_MSG    0x0004 ///< instead of a warning, log the exception to the output window
#define EXC_SILENT 0x0008 ///< do not warn or log to the output window
//@}

  /// Should we break on the exception?
  bool break_on(void) const { return (flags & EXC_BREAK) != 0; }

  /// Should we handle the exception?
  bool handle(void) const { return (flags & EXC_HANDLE) != 0; }

  qstring name;           ///< Exception standard name
  qstring desc;           ///< Long message used to display info about the exception

  exception_info_t(void) : code(0), flags(0) {}
  exception_info_t(uint _code, uint32 _flags, const char *_name, const char *_desc)
    : code(_code), flags(_flags), name(_name), desc(_desc) {}
};
DECLARE_TYPE_AS_MOVABLE(exception_info_t);
typedef qvector<exception_info_t> excvec_t; ///< vector of exception info objects

/// Structure to hold a register value.
/// Small values (up to 64-bit integers and floating point values) use
/// #RVT_INT and #RVT_FLOAT types. For bigger values the bytes() vector is used.
struct regval_t
{
  int32 rvtype;                       ///< one of \ref RVT_
/// \defgroup RVT_ Register value types
/// Used by regval_t::rvtype
//@{
#define RVT_INT    (-1)               ///< integer
#define RVT_FLOAT  (-2)               ///< floating point.
                                      ///< other values mean custom data type
//@}
#ifndef SWIG
  union
  {
#endif //SWIG
    uint64 ival;                      ///< 8:  integer value
    uint16 fval[6];                   ///< 12: floating point value in the internal representation (see ieee.h)
#ifndef SWIG
    uchar reserve[sizeof(bytevec_t)]; ///< bytevec_t: custom data type (use bytes() to access it)
  };
#endif //SWIG
  regval_t(void) : rvtype(RVT_INT), ival(~uint64(0)) {}
  ~regval_t(void) { clear(); }
  regval_t(const regval_t &r) : rvtype(RVT_INT) { *this = r; }

  /// Assign this regval to the given value
  regval_t &operator = (const regval_t &r)
  {
    if ( this == &r )
      return *this;
    if ( r.rvtype >= 0 )
    {
      if ( rvtype >= 0 )
        bytes() = r.bytes();
      else
        new (&bytes()) bytevec_t(r.bytes());
    }
    else // r.rvtype < 0
    {
      if ( rvtype >= 0 )
        bytes().~bytevec_t();
      memcpy(fval, r.fval, sizeof(fval));
    }
    rvtype = r.rvtype;
    return *this;
  }

  /// Clear register value
  void clear(void)
  {
    if ( rvtype >= 0 )
    {
      bytes().~bytevec_t();
      rvtype = RVT_INT;
    }
  }

  /// Compare two regvals with '=='
  bool operator == (const regval_t &r) const
  {
    if ( rvtype == r.rvtype )
    {
      if ( rvtype == RVT_INT )
        return ival == r.ival;
      return memcmp(get_data(), r.get_data(), get_data_size()) == 0;
    }
    return false;
  }

  /// Compare two regvals with '!='
  bool operator != (const regval_t &r) const { return !(*this == r); }

  /// Set this = r and r = this
  void swap(regval_t &r) { qswap(*this, r); }

  /// Use set_int()
  void _set_int(uint64 x) { ival = x; }
  /// Use set_float()
  void _set_float(const ushort *x) { memcpy(fval, x, sizeof(fval)); rvtype = RVT_FLOAT; }
  /// Use set_bytes(const uchar *, size_t)
  void _set_bytes(const uchar *data, size_t size) { new (&bytes()) bytevec_t(data, size); rvtype = 0; }
  /// Use set_bytes(const bytevec_t &)
  void _set_bytes(const bytevec_t &v) { new (&bytes()) bytevec_t(v); rvtype = 0; }
  /// Use set_bytes(void)
  bytevec_t &_set_bytes(void) { new (&bytes()) bytevec_t; rvtype = 0; return bytes(); }

  /// \name Setters
  /// These functions ensure that the previous value is cleared
  //@{
  /// Set int value (ival)
  void set_int(uint64 x) { clear(); _set_int(x); }
  /// Set float value (fval)
  void set_float(const ushort *x) { clear(); _set_float(x); }
  /// Set custom regval with raw data
  void set_bytes(const uchar *data, size_t size) { clear(); _set_bytes(data, size); }
  /// Set custom value with existing bytevec
  void set_bytes(const bytevec_t &v) { clear(); _set_bytes(v); }
  /// Initialize this regval to an empty custom value
  bytevec_t &set_bytes(void) { clear(); _set_bytes(); return bytes(); }
  //@}

  /// \name Getters
  //@{
  /// Get custom value
        bytevec_t &bytes(void)       { return *(bytevec_t *)reserve; }
  /// Get const custom value
  const bytevec_t &bytes(void) const { return *(bytevec_t *)reserve; }
  /// Get pointer to value
        void *get_data(void)       { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  /// Get const pointer to value
  const void *get_data(void) const { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  /// Get size of value
  size_t get_data_size(void) const { return rvtype >= 0 ? bytes().size() : rvtype == RVT_INT ? sizeof(ival) : sizeof(fval); }
  //@}
};
DECLARE_TYPE_AS_MOVABLE(regval_t);
typedef qvector<regval_t> regvals_t; ///< vector register value objects

/// Instruction operand information
struct idd_opinfo_t
{
  bool modified;        ///< the operand is modified (written) by the instruction
  ea_t ea;              ///< operand address (#BADADDR - no address)
  regval_t value;       ///< operand value. custom data is represented by 'bytes'.
  int debregidx;        ///< for custom data: index of the corresponding register in dbg->_registers
  int value_size;       ///< size of the value in bytes

  idd_opinfo_t(void) : modified(false), ea(BADADDR), debregidx(-1), value_size(0) {}
};

/// Call stack trace information
struct call_stack_info_t
{
  ea_t callea;          ///< the address of the call instruction.
                        ///< for the 0th frame this is usually just the current value of EIP.
  ea_t funcea;          ///< the address of the called function
  ea_t fp;              ///< the value of the frame pointer of the called function
  bool funcok;          ///< is the function present?
  bool operator==(const call_stack_info_t &r) const
  {
    return callea == r.callea
        && funcea == r.funcea
        && funcok == r.funcok
        && fp     == r.fp;
  }
  bool operator!=(const call_stack_info_t &r) const { return !(*this == r); }
};

DECLARE_TYPE_AS_MOVABLE(call_stack_info_t);
/// Describes a call stack
struct call_stack_t : public qvector<call_stack_info_t>
{
  bool dirty;           ///< is the stack trace obsolete?
};


/// Call a function from the debugged application.
/// \param[out] r   function return value
///                   - for #APPCALL_MANUAL, r will hold the new stack point value
///                   - for #APPCALL_DEBEV, r will hold the exception information upon failure
///                                   and the return code will be eExecThrow
/// \param func_ea  address to call
/// \param tid      thread to use. #NO_THREAD means to use the current thread
/// \param ptif     pointer to type of the function to call
/// \param argv     array of arguments
/// \param argnum   number of actual arguments
/// \return #eOk if successful, otherwise an error code

idaman error_t ida_export dbg_appcall(
        idc_value_t *retval,
        ea_t func_ea,
        thid_t tid,
        const tinfo_t *ptif,
        idc_value_t *argv,
        size_t argnum);


/// Cleanup after manual appcall.
/// \param tid  thread to use. #NO_THREAD means to use the current thread
/// The application state is restored as it was before calling the last appcall().
/// Nested appcalls are supported.
/// \return #eOk if successful, otherwise an error code

idaman error_t ida_export cleanup_appcall(thid_t tid);


/// Return values for get_debug_event()
enum gdecode_t
{
  GDE_ERROR = -1,       ///< error
  GDE_NO_EVENT,         ///< no debug events are available
  GDE_ONE_EVENT,        ///< got one event, no more available yet
  GDE_MANY_EVENTS,      ///< got one event, more events available
};

/// Input argument for update_bpts()
struct update_bpt_info_t
{
  ea_t ea;              ///< in: bpt address
  bytevec_t orgbytes;   ///< in(del), out(add): original bytes (only for swbpts)
  bpttype_t type;       ///< in: bpt type
  int size;             ///< in: bpt size (only for hwbpts)
  uchar code;           ///< in: 0. #BPT_SKIP entries must be skipped by the debugger module
                        ///< out: \ref BPT_
};
typedef qvector<update_bpt_info_t> update_bpt_vec_t; ///< vector of update breakpoint info objects

/// Input argument for update_lowcnds().
/// Server-side low-level breakpoint conditions
struct lowcnd_t
{
  ea_t ea;              ///< address of the condition
  qstring cndbody;      ///< new condition. empty means 'remove condition'
                        ///< the following fields are valid only if condition is not empty:
  bpttype_t type;       ///< existing breakpoint type
  bytevec_t orgbytes;   ///< original bytes (if type==#BPT_SOFT)
  insn_t cmd;           ///< decoded instruction at 'ea'
                        ///< (used for processors without single step feature, e.g. arm)
  bool compiled;        ///< has 'cndbody' already been compiled?
  int size;             ///< breakpoint size (if type!=#BPT_SOFT)
};
typedef qvector<lowcnd_t> lowcnd_vec_t; ///< vector of low-level breakpoint conditions

//====================================================================
/// How to resume the application. The corresponding bit for \ref DBG_FLAG_
/// must be set in order to use a resume mode.
enum resume_mode_t
{
  RESMOD_NONE,    ///< no stepping, run freely
  RESMOD_INTO,    ///< step into call (the most typical single stepping)
  RESMOD_OVER,    ///< step over call
  RESMOD_OUT,     ///< step out of the current function (run until return)
  RESMOD_SRCINTO, ///< until control reaches a different source line
  RESMOD_SRCOVER, ///< next source line in the current stack frame
  RESMOD_SRCOUT,  ///< next source line in the previous stack frame
  RESMOD_USER,    ///< step out to the user code
  RESMOD_HANDLE,  ///< step into the exception handler
  RESMOD_MAX,
};

//====================================================================
/// This structure describes a debugger API module.
/// (functions needed to debug a process on a specific
///  operating system).
///
/// The address of this structure must be put into the ::dbg variable by
/// the plugin_t::init() function of the debugger plugin.
struct debugger_t
{
  int version;                        ///< Expected kernel version,
                                      ///<   should be #IDD_INTERFACE_VERSION
  const char *name;                   ///< Short debugger name like win32 or linux
  int id;                             ///< one of \ref DEBUGGER_ID_
/// \defgroup DEBUGGER_ID_ Debugger API module id
/// Used by debugger_t::id
//@{
#define DEBUGGER_ID_X86_IA32_WIN32_USER              0 ///< Userland win32 processes (win32 debugging APIs)
#define DEBUGGER_ID_X86_IA32_LINUX_USER              1 ///< Userland linux processes (ptrace())
#define DEBUGGER_ID_ARM_WINCE_ASYNC                  2 ///< Windows CE ARM (ActiveSync transport)
#define DEBUGGER_ID_X86_IA32_MACOSX_USER             3 ///< Userland MAC OS X processes
#define DEBUGGER_ID_ARM_EPOC_USER                    4 ///< Symbian OS
#define DEBUGGER_ID_ARM_IPHONE_USER                  5 ///< iPhone 1.x
#define DEBUGGER_ID_X86_IA32_BOCHS                   6 ///< BochsDbg.exe 32
#define DEBUGGER_ID_6811_EMULATOR                    7 ///< MC6812 emulator (beta)
#define DEBUGGER_ID_GDB_USER                         8 ///< GDB remote
#define DEBUGGER_ID_WINDBG                           9 ///< WinDBG using Microsoft Debug engine
#define DEBUGGER_ID_X86_DOSBOX_EMULATOR             10 ///< Dosbox MS-DOS emulator
#define DEBUGGER_ID_ARM_LINUX_USER                  11 ///< Userland arm linux
#define DEBUGGER_ID_TRACE_REPLAYER                  12 ///< Fake debugger to replay recorded traces
#define DEBUGGER_ID_ARM_WINCE_TCPIP                 13 ///< Windows CE ARM (TPC/IP transport)
#define DEBUGGER_ID_X86_PIN_TRACER                  14 ///< PIN Tracer module
#define DEBUGGER_ID_DALVIK_USER                     15 ///< Dalvik
//@}

  const char *processor;              ///< Required processor name.
                                      ///< Used for instant debugging to load the correct
                                      ///< processor module

  uint32 flags;                             ///< \ref DBG_FLAG_
/// \defgroup DBG_FLAG_ Debugger module features
/// Used by debugger_t::flags
//@{
#define DBG_FLAG_REMOTE       0x00000001    ///< Remote debugger (requires remote host name unless #DBG_FLAG_NOHOST)
#define DBG_FLAG_NOHOST       0x00000002    ///< Remote debugger with does not require network params (host/port/pass).
                                            ///< (a unique device connected to the machine)
#define DBG_FLAG_FAKE_ATTACH  0x00000004    ///< ::PROCESS_ATTACH is a fake event
                                            ///< and does not suspend the execution
#define DBG_FLAG_HWDATBPT_ONE 0x00000008    ///< Hardware data breakpoints are
                                            ///< one byte size by default
#define DBG_FLAG_CAN_CONT_BPT 0x00000010    ///< Debugger knows to continue from a bpt.
                                            ///< This flag also means that the debugger module
                                            ///< hides breakpoints from ida upon read_memory
#define DBG_FLAG_NEEDPORT     0x00000020    ///< Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
#define DBG_FLAG_DONT_DISTURB 0x00000040    ///< Debugger can handle only
                                            ///<   get_debug_event(),
                                            ///<   prepare_to_pause_process(),
                                            ///<   exit_process().
                                            ///< when the debugged process is running.
                                            ///< The kernel may also call service functions
                                            ///< (file I/O, map_address, etc)
#define DBG_FLAG_SAFE         0x00000080    ///< The debugger is safe (probably because it just emulates the application
                                            ///< without really running it)
#define DBG_FLAG_CLEAN_EXIT   0x00000100    ///< IDA must suspend the application and remove
                                            ///< all breakpoints before terminating the application.
                                            ///< Usually this is not required because the application memory
                                            ///< disappears upon termination.
#define DBG_FLAG_USE_SREGS    0x00000200    ///< Take segment register values into account (non flat memory)
#define DBG_FLAG_NOSTARTDIR   0x00000400    ///< Debugger module doesn't use startup directory
#define DBG_FLAG_NOPARAMETERS 0x00000800    ///< Debugger module doesn't use commandline parameters
#define DBG_FLAG_NOPASSWORD   0x00001000    ///< Remote debugger doesn't use password
#define DBG_FLAG_CONNSTRING   0x00002000    ///< Display "Connection string" instead of "Hostname" and hide the "Port" field
#define DBG_FLAG_SMALLBLKS    0x00004000    ///< If set, IDA uses 256-byte blocks for caching memory contents.
                                            ///< Otherwise, 1024-byte blocks are used
#define DBG_FLAG_MANMEMINFO   0x00008000    ///< If set, manual memory region manipulation commands
                                            ///< will be available. Use this bit for debugger modules
                                            ///< that can not return memory layout information
#define DBG_FLAG_EXITSHOTOK   0x00010000    ///< IDA may take a memory snapshot at ::PROCESS_EXIT event
#define DBG_FLAG_VIRTHREADS   0x00020000    ///< Thread IDs may be shuffled after each debug event.
                                            ///< (to be used for virtual threads that represent cpus for windbg kmode)
#define DBG_FLAG_LOWCNDS      0x00040000    ///< Low level breakpoint conditions are supported.
#define DBG_FLAG_DEBTHREAD    0x00080000    ///< Supports creation of a separate thread in ida
                                            ///< for the debugger (the debthread).
                                            ///< Most debugger functions will be called from debthread (exceptions are marked below)
                                            ///< The debugger module may directly call only #THREAD_SAFE functions.
                                            ///< To call other functions please use execute_sync().
                                            ///< The debthread significantly increases debugging
                                            ///< speed, especially if debug events occur frequently (to be tested)
#define DBG_FLAG_DEBUG_DLL    0x00100000    ///< Can debug standalone DLLs.
                                            ///< For example, Bochs debugger can debug any snippet of code
#define DBG_FLAG_FAKE_MEMORY  0x00200000    ///< get_memory_info()/read_memory()/write_memory() work with the idb.
                                            ///< (there is no real process to read from, as for the replayer module)
                                            ///< the kernel will not call these functions if this flag is set.
                                            ///< however, third party plugins may call them, they must be implemented.
#define DBG_FLAG_ANYSIZE_HWBPT 0x00400000   ///< The debugger supports arbitrary size hardware breakpoints.
#define DBG_FLAG_TRACER_MODULE 0x00800000   ///< The module is a tracer, not a full featured debugger module
#define DBG_FLAG_PREFER_SWBPTS 0x01000000   ///< Prefer to use software breakpoints
//@}

  bool is_remote(void) const { return (flags & DBG_FLAG_REMOTE) != 0; }
  bool must_have_hostname(void) const
    { return (flags & (DBG_FLAG_REMOTE|DBG_FLAG_NOHOST)) == DBG_FLAG_REMOTE; }
  bool can_continue_from_bpt(void) const
    { return (flags & DBG_FLAG_CAN_CONT_BPT) != 0; }
  bool may_disturb(void) const
    { return (flags & DBG_FLAG_DONT_DISTURB) == 0; }
  bool is_safe(void) const
    { return (flags & DBG_FLAG_SAFE) != 0; }
  bool use_sregs(void) const
    { return (flags & DBG_FLAG_USE_SREGS) != 0; }
  size_t cache_block_size(void) const
    { return (flags & DBG_FLAG_SMALLBLKS) != 0 ? 256 : 1024; }
  bool use_memregs(void) const
    { return (flags & DBG_FLAG_MANMEMINFO) != 0; }
  bool may_take_exit_snapshot(void) const
    { return (flags & DBG_FLAG_EXITSHOTOK) != 0; }
  bool virtual_threads(void) const
    { return (flags & DBG_FLAG_VIRTHREADS) != 0; }
  bool supports_lowcnds(void) const
    { return (flags & DBG_FLAG_LOWCNDS) != 0; }
  bool supports_debthread(void) const
    { return (flags & DBG_FLAG_DEBTHREAD) != 0; }
  bool can_debug_standalone_dlls(void) const
    { return (flags & DBG_FLAG_DEBUG_DLL) != 0; }
  bool fake_memory(void) const
    { return (flags & DBG_FLAG_FAKE_MEMORY) != 0; }

  const char **register_classes;             ///< Array of register class names
  int register_classes_default;              ///< Mask of default printed register classes
  register_info_t *_registers;               ///< Array of registers. Use registers() to access it
  int registers_size;                        ///< Number of registers

  int memory_page_size;                      ///< Size of a memory page

  const uchar *bpt_bytes;                    ///< Array of bytes for a breakpoint instruction
  uchar bpt_size;                            ///< Size of this array
  uchar filetype;                            ///< for miniidbs: use this value
                                             ///< for the file type after attaching
                                             ///< to a new process
  ushort resume_modes;                       ///< \ref DBG_RESMOD_
/// \defgroup DBG_RESMOD_ Resume modes
/// Used by debugger_t::resume_modes
//@{
#define DBG_RESMOD_STEP_INTO      0x0001     ///< ::RESMOD_INTO is available
#define DBG_RESMOD_STEP_OVER      0x0002     ///< ::RESMOD_OVER is available
#define DBG_RESMOD_STEP_OUT       0x0004     ///< ::RESMOD_OUT is available
#define DBG_RESMOD_STEP_SRCINTO   0x0008     ///< ::RESMOD_SRCINTO is available
#define DBG_RESMOD_STEP_SRCOVER   0x0010     ///< ::RESMOD_SRCOVER is available
#define DBG_RESMOD_STEP_SRCOUT    0x0020     ///< ::RESMOD_SRCOUT is available
#define DBG_RESMOD_STEP_USER      0x0040     ///< ::RESMOD_USER is available
#define DBG_RESMOD_STEP_HANDLE    0x0080     ///< ::RESMOD_HANDLE is available
//@}
  bool is_resmod_avail(int resmod) const
    { return (resume_modes & (1 << (resmod - 1))) != 0; }

  // A function for accessing the '_registers' array
  inline register_info_t &registers(int idx)
  {
    return _registers[idx];
  }

#if !defined(_MSC_VER)  // this compiler complains :(
  static const int default_port_number = 23946;
#define DEBUGGER_PORT_NUMBER debugger_t::default_port_number
#else
#define DEBUGGER_PORT_NUMBER 23946
#endif

  /// Initialize debugger.
  /// This function is called from the main thread.
  /// \return success
  bool (idaapi *init_debugger)(const char *hostname, int portnum, const char *password);

  /// Terminate debugger.
  /// This function is called from the main thread.
  /// \return success
  bool (idaapi *term_debugger)(void);

  /// Return information about the running processes.
  /// This function is called from the main thread.
  /// \retval 1  ok
  /// \retval 0  failed
  /// \retval -1 network error
  int (idaapi *get_processes)(procinfo_vec_t *procs);

  /// Start an executable to debug.
  /// This function is called from debthread.
  /// \param path              path to executable
  /// \param args              arguments to pass to executable
  /// \param startdir          current directory of new process
  /// \param dbg_proc_flags    \ref DBG_PROC_
  /// \param input_path        path to database input file.
  ///                          (not always the same as 'path' - e.g. if you're analyzing
  ///                          a dll and want to launch an executable that loads it)
  /// \param input_file_crc32  CRC value for 'input_path'
  /// \retval  1                    ok
  /// \retval  0                    failed
  /// \retval -2                    file not found (ask for process options)
  /// \retval  1 | #CRC32_MISMATCH  ok, but the input file crc does not match
  /// \retval -1                    network error
  int (idaapi *start_process)(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32);
/// \defgroup DBG_PROC_ Debug process flags
/// Passed as 'dbg_proc_flags' parameter to debugger_t::start_process
//@{
#define DBG_PROC_IS_DLL 0x01            ///< database contains a dll (not exe)
#define DBG_PROC_IS_GUI 0x02            ///< using gui version of ida
#define DBG_PROC_32BIT  0x04            ///< application is 32-bit
#define DBG_PROC_64BIT  0x08            ///< application is 64-bit
#define DBG_NO_TRACE    0x10            ///< do not trace the application (mac/linux)
#define DBG_HIDE_WINDOW 0x20            ///< application should be hidden on startup (windows)
//@}
#define CRC32_MISMATCH  0x40000000      ///< crc32 mismatch bit (see return values for debugger_t::start_process)

  /// Attach to an existing running process.
  /// event_id should be equal to -1 if not attaching to a crashed process.
  /// This function is called from debthread.
  /// \param pid               process id to attach
  /// \param event_id          event to trigger upon attaching
  /// \param dbg_proc_flags    \ref DBG_PROC_
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *attach_process)(pid_t pid, int event_id, int dbg_proc_flags);

  /// Detach from the debugged process.
  /// May be called while the process is running or suspended.
  /// Must detach from the process in any case.
  /// The kernel will repeatedly call get_debug_event() and until ::PROCESS_DETACH.
  /// In this mode, all other events will be automatically handled and process will be resumed.
  /// This function is called from debthread.
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *detach_process)(void);

  /// Rebase database if the debugged program has been rebased by the system.
  /// This function is called from the main thread.
  void (idaapi *rebase_if_required_to)(ea_t new_base);

  /// Prepare to pause the process.
  /// Normally the next get_debug_event() will pause the process
  /// If the process is sleeping then the pause will not occur
  /// until the process wakes up. The interface should take care of
  /// this situation.
  /// If this function is absent, then it won't be possible to pause the program.
  /// This function is called from debthread.
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *prepare_to_pause_process)(void);

  /// Stop the process.
  /// May be called while the process is running or suspended.
  /// Must terminate the process in any case.
  /// The kernel will repeatedly call get_debug_event() and until ::PROCESS_EXIT.
  /// In this mode, all other events will be automatically handled and process will be resumed.
  /// This function is called from debthread.
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *exit_process)(void);

  /// Get a pending debug event and suspend the process.
  /// This function will be called regularly by IDA.
  /// This function is called from debthread.
  /// IMPORTANT: commdbg does not expect immediately after a BPT-related event
  /// any other event with the same thread/IP - this can cause erroneous
  /// restoring of a breakpoint before resume
  /// (the bug was encountered 24.02.2015 in pc_linux_upx.elf)
  gdecode_t (idaapi *get_debug_event)(debug_event_t *event, int timeout_ms);

  /// Continue after handling the event.
  /// This function is called from debthread.
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *continue_after_event)(const debug_event_t *event);

  /// Set exception handling.
  /// This function is called from debthread or the main thread.
  void (idaapi *set_exception_info)(const exception_info_t *info, int qty);

  /// This function will be called by the kernel each time
  /// it has stopped the debugger process and refreshed the database.
  /// The debugger module may add information to the database if it wants.
  ///
  /// The reason for introducing this function is that when an event line
  /// LOAD_DLL happens, the database does not reflect the memory state yet
  /// and therefore we can't add information about the dll into the database
  /// in the get_debug_event() function.
  /// Only when the kernel has adjusted the database we can do it.
  /// Example: for imported PE DLLs we will add the exported function
  /// names to the database.
  ///
  /// This function pointer may be absent, i.e. NULL.
  /// This function is called from the main thread.
  void (idaapi *stopped_at_debug_event)(bool dlls_added);

  /// \name Threads
  /// The following functions manipulate threads.
  /// These functions are called from debthread.
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  //@{
  int (idaapi *thread_suspend) (thid_t tid); ///< Suspend a running thread
  int (idaapi *thread_continue)(thid_t tid); ///< Resume a suspended thread
  int (idaapi *set_resume_mode)(thid_t tid, resume_mode_t resmod); ///< Specify resume action
  //@}

  /// Read thread registers.
  /// This function is called from debthread.
  /// \param tid      thread id
  /// \param clsmask  bitmask of register classes to read
  /// \param values   pointer to vector of regvals for all registers.
  ///                 regval is assumed to have debugger_t::registers_size elements
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *read_registers)(thid_t tid, int clsmask, regval_t *values);

  /// Write one thread register.
  /// This function is called from debthread.
  /// \param tid     thread id
  /// \param regidx  register index
  /// \param value   new value of the register
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *write_register)(thid_t tid, int regidx, const regval_t *value);

  /// Get information about the base of a segment register.
  /// Currently used by the IBM PC module to resolve references like fs:0.
  /// This function is called from debthread.
  /// \param answer      pointer to the answer. can't be NULL.
  /// \param tid         thread id
  /// \param sreg_value  value of the segment register (returned by get_reg_val())
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *thread_get_sreg_base)(ea_t *answer, thid_t tid, int sreg_value);

  /// \name Memory manipulation
  /// The following functions manipulate bytes in the memory.
  //@{

  /// Get information on the memory ranges.
  /// The debugger module fills 'ranges'. The returned vector MUST be sorted.
  /// This function is called from debthread.
  /// \retval  -3  use idb segmentation
  /// \retval  -2  no changes
  /// \retval  -1  the process does not exist anymore
  /// \retval   0  failed
  /// \retval   1  new memory layout is returned
  int (idaapi *get_memory_info)(meminfo_vec_t &ranges);

  /// Read process memory.
  /// Returns number of read bytes.
  /// This function is called from debthread.
  /// \retval 0  read error
  /// \retval -1 process does not exist anymore
  ssize_t (idaapi *read_memory)(ea_t ea, void *buffer, size_t size);

  /// Write process memory.
  /// This function is called from debthread.
  /// \return number of written bytes, -1 if fatal error
  ssize_t (idaapi *write_memory)(ea_t ea, const void *buffer, size_t size);

  //@}

  /// Is it possible to set breakpoint?.
  /// This function is called from debthread or from the main thread if debthread
  /// is not running yet.
  /// It is called to verify hardware breakpoints.
  /// \return ref BPT_
  int (idaapi *is_ok_bpt)(bpttype_t type, ea_t ea, int len);
/// \defgroup BPT_ Breakpoint verification codes
/// Return values for debugger_t::is_ok_bpt
//@{
#define BPT_OK           0 ///< breakpoint can be set
#define BPT_INTERNAL_ERR 1 ///< interr occurred when verifying breakpoint
#define BPT_BAD_TYPE     2 ///< bpt type is not supported
#define BPT_BAD_ALIGN    3 ///< alignment is invalid
#define BPT_BAD_ADDR     4 ///< ea is invalid
#define BPT_BAD_LEN      5 ///< bpt len is invalid
#define BPT_TOO_MANY     6 ///< reached max number of supported breakpoints
#define BPT_READ_ERROR   7 ///< failed to read memory at bpt ea
#define BPT_WRITE_ERROR  8 ///< failed to write memory at bpt ea
#define BPT_SKIP         9 ///< update_bpts(): do not process bpt
#define BPT_PAGE_OK     10 ///< update_bpts(): ok, added a page bpt
//@}

  /// Add/del breakpoints.
  /// bpts array contains nadd bpts to add, followed by ndel bpts to del.
  /// This function is called from debthread.
  /// \return number of successfully modified bpts, -1 if network error
  int (idaapi *update_bpts)(update_bpt_info_t *bpts, int nadd, int ndel);

  /// Update low-level (server side) breakpoint conditions.
  /// This function is called from debthread.
  /// \return nlowcnds. -1-network error
  int (idaapi *update_lowcnds)(const lowcnd_t *lowcnds, int nlowcnds);

  /// \name Remote file
  /// Open/close/read a remote file.
  /// These functions are called from the main thread
  //@{
  int  (idaapi *open_file)(const char *file, uint64 *fsize, bool readonly); // -1-error
  void (idaapi *close_file)(int fn);
  ssize_t (idaapi *read_file)(int fn, qoff64_t off, void *buf, size_t size);
  //@}

  /// Map process address.
  /// This function may be absent.
  /// This function is called from debthread.
  /// \param off      offset to map
  /// \param regs     current register values. if regs == NULL, then perform
  ///                 global mapping, which is independent on used registers
  ///                 usually such a mapping is a trivial identity mapping
  /// \param regnum   required mapping. maybe specified as a segment register number
  ///                 or a regular register number if the required mapping can be deduced
  ///                 from it. for example, esp implies that ss should be used.
  /// \return mapped address or #BADADDR
  ea_t (idaapi *map_address)(ea_t off, const regval_t *regs, int regnum);

  /// Set debugger options (parameters that are specific to the debugger module).
  /// See the definition of ::set_options_t for arguments.
  /// See the convenience function in dbg.hpp if you need to call it.
  /// The kernel will call this function after reading the debugger specific
  /// config file (arguments are: keyword="", type=#IDPOPT_STR, value="")
  /// This function is optional.
  /// This function is called from the main thread
  const char *(idaapi *set_dbg_options)(
        const char *keyword,
        int pri,
        int value_type,
        const void *value);


  /// Get pointer to debugger specific functions.
  /// This function returns a pointer to a structure that holds pointers to
  /// debugger module specific functions. For information on the structure
  /// layout, please check the corresponding debugger module. Most debugger
  /// modules return NULL because they do not have any extensions. Available
  /// extensions may be called from plugins.
  /// This function is called from the main thread.
  const void *(idaapi *get_debmod_extensions)(void);


  /// Calculate the call stack trace.
  /// This function is called when the process is suspended and should fill
  /// the 'trace' object with the information about the current call stack.
  /// If this function is missing or returns false, IDA will use the standard
  /// mechanism (based on the frame pointer chain) to calculate the stack trace
  /// This function is called from the main thread.
  /// \return success
  bool (idaapi *update_call_stack)(thid_t tid, call_stack_t *trace);

  /// Call application function.
  /// This function calls a function from the debugged application.
  /// This function is called from debthread
  /// \param func_ea      address to call
  /// \param tid          thread to use
  /// \param fti          type information for the called function
  /// \param nargs        number of actual arguments
  /// \param regargs      information about register arguments
  /// \param stkargs      memory blob to pass as stack arguments (usually contains pointed data)
  ///                     it must be relocated by the callback but not changed otherwise
  /// \param retregs      function return registers.
  /// \param[out] errbuf  the error message. if empty on failure, see 'event'.
  ///                     should not be filled if an appcall exception
  ///                     happened but #APPCALL_DEBEV is set
  /// \param[out] event   the last debug event that occurred during appcall execution
  ///                     filled only if the appcall execution fails and #APPCALL_DEBEV is set
  /// \param options      appcall options, usually taken from \inf{appcall_options}.
  ///                     possible values: combination of \ref APPCALL_  or 0
  /// \return ea of stkargs blob, #BADADDR if failed and errbuf is filled
  ea_t (idaapi *appcall)(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_data_t *fti,
        int nargs,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int options);

/// \defgroup APPCALL_ Appcall options
/// Passed as 'options' parameter to debugger_t::appcall
//@{
#define APPCALL_MANUAL  0x0001  ///< Only set up the appcall, do not run.
                                ///< debugger_t::cleanup_appcall will not be called by ida!
#define APPCALL_DEBEV   0x0002  ///< Return debug event information
#define APPCALL_TIMEOUT 0x0004  ///< Appcall with timeout.
                                ///< If timed out, errbuf will contain "timeout".
                                ///< See #SET_APPCALL_TIMEOUT and #GET_APPCALL_TIMEOUT
/// Set appcall timeout in milliseconds
#define SET_APPCALL_TIMEOUT(msecs)   ((uint(msecs) << 16)|APPCALL_TIMEOUT)
/// Timeout value is contained in high 2 bytes of 'options' parameter
#define GET_APPCALL_TIMEOUT(options) (uint(options) >> 16)
//@}

  /// Cleanup after appcall().
  /// The debugger module must keep the stack blob in the memory until this function
  /// is called. It will be called by the kernel for each successful appcall().
  /// There is an exception: if #APPCALL_MANUAL, IDA may not call cleanup_appcall.
  /// If the user selects to terminate a manual appcall, then cleanup_appcall will be called.
  /// Otherwise, the debugger module should terminate the appcall when the called
  /// function returns.
  /// This function is called from debthread.
  /// \retval  2  ok, there are pending events
  /// \retval  1  ok
  /// \retval  0  failed
  /// \retval -1  network error
  int (idaapi *cleanup_appcall)(thid_t tid);

  /// Evaluate a low level breakpoint condition at 'ea'.
  /// Other evaluation errors are displayed in a dialog box.
  /// This call is rarely used by IDA when the process has already been suspended
  /// for some reason and it has to decide whether the process should be resumed
  /// or definitely suspended because of a breakpoint with a low level condition.
  /// This function is called from debthread.
  /// \retval  1  condition is satisfied
  /// \retval  0  not satisfied
  /// \retval -1  network error
  int (idaapi *eval_lowcnd)(thid_t tid, ea_t ea);

  /// This function is called from main thread
  ssize_t (idaapi *write_file)(int fn, qoff64_t off, const void *buf, size_t size);

  /// Perform a debugger-specific function.
  /// This function is called from debthread
  int (idaapi *send_ioctl)(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);

  /// Enable/Disable tracing.
  /// "trace_flags" can be a set of STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE.
  /// See thread_t::trace_mode in debugger.h.
  /// This function is called from the main thread.
  bool (idaapi *dbg_enable_trace)(thid_t tid, bool enable, int trace_flags);

  /// Is tracing enabled? ONLY used for tracers.
  /// "trace_bit" can be one of the following: STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE
  bool (idaapi *is_tracing_enabled)(thid_t tid, int tracebit);

  /// Execute a command on the remote computer.
  /// \return exit code
  int (idaapi *rexec)(const char *cmdline);

  /// Get (store to out_pattrs) process/debugger-specific runtime attributes.
  /// This function is called from main thread.
  void (idaapi *get_debapp_attrs)(debapp_attrs_t *out_pattrs);

  /// Get the path to a file containing source debug info for the given module.
  /// This allows srcinfo providers to call into the debugger when looking for debug info.
  /// It is useful in certain cases like the iOS debugger, which is a remote debugger but
  /// the remote debugserver does not provide dwarf info. So, we allow the debugger client
  /// to decide where to look for debug info locally.
  /// \param path  output path (file might not exist)
  /// \param base  base address of a module in the target process
  /// \return success, result stored in 'path'
  bool (idaapi *get_srcinfo_path)(qstring *path, ea_t base);
};

#ifdef __X64__
  CASSERT(sizeof(debugger_t) == 424);
#else
  CASSERT(sizeof(debugger_t) == 216);
#endif


#define RQ_MASKING  0x0001  // masking step handler: unless errors, tmpbpt handlers won't be called
                            // should be used only with request_internal_step()
#define RQ_SUSPEND  0x0002  // suspending step handler: suspends the app
                            // handle_debug_event: suspends the app
#define RQ_NOSUSP   0x0000  // running step handler: continues the app
#define RQ_IGNWERR  0x0004  // ignore breakpoint write failures
#define RQ_SILENT   0x0008  // all: no dialog boxes
#define RQ_VERBOSE  0x0000  // all: display dialog boxes
#define RQ_SWSCREEN 0x0010  // handle_debug_event: switch screens
#define RQ__NOTHRRF 0x0020  // handle_debug_event: do not refresh threads. temporary flag
                            // must go away as soon as we straighten dstate.
#define RQ_PROCEXIT 0x0040  // snapshots: the process is exiting
#define RQ_IDAIDLE  0x0080  // handle_debug_event: ida is idle
#define RQ_SUSPRUN  0x0100  // handle_debug_event: suspend at PROCESS_START
#define RQ_RESUME   0x0200  // handle_debug_event: resume application
#define RQ_RESMOD   0xF000  // resume_mode_t
#define RQ_RESMOD_SHIFT 12
#define RQ_INTO (RESMOD_INTO << RQ_RESMOD_SHIFT)

#endif // _IDD_HPP
