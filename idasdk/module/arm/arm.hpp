/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2002 by Ilfak Guilfanov, Datarescue.
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _ARM_HPP
#define _ARM_HPP

#include "../idaidp.hpp"
#include <idd.hpp>
#include <dbg.hpp>
#include <srarea.hpp>
#include <typeinf.hpp>
#include "ins.hpp"
#include "arm_arch.hpp"

#pragma pack(push, 4)
//---------------------------------
// ARM cmd.auxpref bits
#define aux_cond        0x0001  // set condition codes (S postfix is required)
#define aux_byte        0x0002  // byte transfer (B postfix is required)
#define aux_npriv       0x0004  // non-privileged transfer (T postfix is required)
#define aux_regsh       0x0008  // shift count is held in a register (see o_shreg)
#define aux_negoff      0x0010  // memory offset is negated in LDR,STR
#define aux_immcarry    0x0010  // carry flag is set to bit 31 of the immediate operand (see may_set_carry)
#define aux_wback       0x0020  // write back (! postfix is required)
#define aux_wbackldm    0x0040  // write back for LDM/STM (! postfix is required)
#define aux_postidx     0x0080  // post-indexed mode in LDR,STR
#define aux_ltrans      0x0100  // long transfer in LDC/STC (L postfix is required)
#define aux_wimm        0x0200  // thumb32 wide encoding of immediate constant
#define aux_sb          0x0400  // signed byte (SB postfix)
#define aux_sh          0x0800  // signed halfword (SH postfix)
#define aux_sw          0x0C00  // signed word (SW postfix)
#define aux_h           0x1000  // halfword (H postfix)
#define aux_p           0x2000  // priviledged (P postfix)
#define aux_coproc      0x4000  // coprocessor instruction
#define aux_wide        0x8000  // thumb32 instruction (.W suffix)

#define UAS_GNU         0x0001  // GNU assembler

inline bool is_gas(void)
{
  return (ash.uflag & UAS_GNU) != 0;
}

//---------------------------------

#define it_mask         insnpref        // mask field of IT-insn

// data type of NEON and vector VFP instructions (for the suffix)
enum neon_datatype_t ENUM_SIZE(char)
{
  DT_NONE = 0,
  DT_8,
  DT_16,
  DT_32,
  DT_64,
  DT_S8,
  DT_S16,
  DT_S32,
  DT_S64,
  DT_U8,
  DT_U16,
  DT_U32,
  DT_U64,
  DT_I8,
  DT_I16,
  DT_I32,
  DT_I64,
  DT_P8,
  DT_P16,
  DT_F16,
  DT_F32,
  DT_F64,
};

// we will store the suffix in insnpref, since it's used only by the IT instruction
// if we need two suffixes (VCVTxx), we'll store the second one in Op1.specflag1
inline void set_neon_suffix(neon_datatype_t suf1, neon_datatype_t suf2 = DT_NONE)
{
  if ( suf1 != DT_NONE )
  {
    cmd.insnpref = char(0x80 | suf1);
    if ( suf2 != DT_NONE )
      cmd.Op1.specflag1 = suf2;
  }
}
inline neon_datatype_t get_neon_suffix()  { if ( cmd.insnpref & 0x80 ) return neon_datatype_t(cmd.insnpref & 0x7F); else return DT_NONE; }
inline neon_datatype_t get_neon_suffix2() { return neon_datatype_t(cmd.Op1.specflag1); }

// Operand types:
#define o_shreg         o_idpspec0         // Shifted register
                                           //  op.reg    - register
#define shtype          specflag2          //  op.shtype - shift type
#define shreg(x)        uchar(x.specflag1) //  op.shreg  - shift register
#define shcnt           value              //  op.shcnt  - shift counter

#define ishtype         specflag2          // o_imm - shift type
#define ishcnt          specval            // o_imm - shift counter

#define secreg(x)       uchar(x.specflag1) // o_phrase: the second register is here
#define ralign          specflag3          // o_phrase, o_displ: NEON alignment (power-of-two bytes, i.e. 8*(1<<a))
                                           // minimal alignment is 16 (a==1)

#define simd_sz         specflag1          // o_reg: SIMD vector element size
                                           // 0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits)
                                           // number of lanes is derived from the vector size (dtype)
#define simd_idx        specflag3          // o_reg: SIMD scalar index plus 1 (Vn.H[i])

// o_phrase: the second register is held in secreg (specflag1)
//           the shift type is in shtype (specflag2)
//           the shift counter is in shcnt (value)

#define o_reglist       o_idpspec1         // Register list (for LDM/STM)
#define reglist         specval            // The list is in op.specval
#define uforce          specflag1          // PSR & force user bit (^ suffix)

#define o_creglist      o_idpspec2         // Coprocessor register list (for CDP)
#define CRd             reg                //
#define CRn             specflag1          //
#define CRm             specflag2          //

#define o_creg          o_idpspec3         // Coprocessor register (for LDC/STC)

#define o_fpreglist     o_idpspec4         // Floating point register list
#define fpregstart      reg                // First register
#define fpregcnt        value              // number of registers; 0: single register (NEON scalar)
#define fpregstep       specflag2          // register spacing (0: {Dd, Dd+1,... }, 1: {Dd, Dd+2, ...} etc)
#define fpregindex      specflag3          // NEON scalar index plus 1 (Dd[x])
#define NOINDEX         (char)254          // no index - all lanes (Dd[])

#define o_text          o_idpspec5         // Arbitrary text stored in the operand
                                           // structure starting at the 'value' field
                                           // up to 16 bytes (with terminating zero)
#define o_cond          o_idpspec5+1       // ARM condition as an operand
                                           // condition is stored in 'value' field

// The processor number of coprocessor instructions is held in cmd.Op1.specflag1:
#define procnum         specflag1

// bits stored in specflag1 for APSR register
#define APSR_nzcv       0x01
#define APSR_q          0x02
#define APSR_g          0x04
// for SPSR/CPSR
#define CPSR_c          0x01
#define CPSR_x          0x02
#define CPSR_s          0x04
#define CPSR_f          0x08
// for banked registers (R8-R12, SP, LR/ELR, SPSR), this flag is set
#define BANKED_MODE     0x80 // the mode is in low 5 bits (arm_mode_t)

//------------------------------------------------------------------
// Shift types:
enum shift_t
{
  LSL,          // logical left         LSL #0 - don't shift
  LSR,          // logical right        LSR #0 means LSR #32
  ASR,          // arithmetic right     ASR #0 means ASR #32
  ROR,          // rotate right         ROR #0 means RRX
  RRX,          // extended rotate right

  // ARMv8 shifts
  MSL,          // masked shift left (ones are shifted in from the right)

  // extending register operations
  UXTB,
  UXTH,
  UXTW,
  UXTX,         // alias for LSL
  SXTB,
  SXTH,
  SXTW,
  SXTX,
};

#define dt_half         0x7f  // special value for op_t.dtyp for half-precision registers
//------------------------------------------------------------------
// Bit definitions. Just for convenience:
#define BIT0    0x00000001L
#define BIT1    0x00000002L
#define BIT2    0x00000004L
#define BIT3    0x00000008L
#define BIT4    0x00000010L
#define BIT5    0x00000020L
#define BIT6    0x00000040L
#define BIT7    0x00000080L
#define BIT8    0x00000100L
#define BIT9    0x00000200L
#define BIT10   0x00000400L
#define BIT11   0x00000800L
#define BIT12   0x00001000L
#define BIT13   0x00002000L
#define BIT14   0x00004000L
#define BIT15   0x00008000L
#define BIT16   0x00010000L
#define BIT17   0x00020000L
#define BIT18   0x00040000L
#define BIT19   0x00080000L
#define BIT20   0x00100000L
#define BIT21   0x00200000L
#define BIT22   0x00400000L
#define BIT23   0x00800000L
#define BIT24   0x01000000L
#define BIT25   0x02000000L
#define BIT26   0x04000000L
#define BIT27   0x08000000L
#define BIT28   0x10000000L
#define BIT29   0x20000000L
#define BIT30   0x40000000L
#define BIT31   0x80000000L

#define HEX__(n) 0x##n##LU

/* 8-bit conversion function */
#define B8__(x) ((x&0x0000000FLU)?1:0) \
+((x&0x000000F0LU)?2:0) \
+((x&0x00000F00LU)?4:0) \
+((x&0x0000F000LU)?8:0) \
+((x&0x000F0000LU)?16:0) \
+((x&0x00F00000LU)?32:0) \
+((x&0x0F000000LU)?64:0) \
+((x&0xF0000000LU)?128:0)

// for upto 8-bit binary constants
#define B8(d) ((unsigned char)B8__(HEX__(d)))

// for upto 16-bit binary constants, MSB first
#define B16(dmsb,dlsb) (((uint16)B8(dmsb)<< 8) | (uint16)B8(dlsb))

// for upto 32-bit binary constants, MSB first
#define B32(dmsb,db2,db3,dlsb) (((uint32)B8(dmsb)<<24) |\
                                ((uint32)B8(db2 )<<16) |\
                                ((uint32)B8(db3 )<< 8) |\
                                         B8(dlsb))

// extract bit numbers high..low from val (inclusive, start from 0)
#define BITS(val, high, low) ( ((val)>>low) & ( (1<<(high-low+1))-1) )

// extract one bit
#define BIT(val, bit) ( ((val)>>bit) & 1 )

// return if mask matches the value
// mask has 1s for important bits and 0s for don't-care bits
// match has actual values for important bits
// e.g. : xx0x0 means mask is 11010 and match is aa0a0
#define MATCH(value, mask, match) ( ((value) & (mask)) == (match) )

//------------------------------------------------------------------
// The condition code of instruction will be kept in cmd.segpref:

#define cond            segpref

//------------------------------------------------------------------
enum RegNo
{
  R0, R1,  R2,  R3,  R4,  R5,  R6,  R7,
  R8, R9, R10, R11, R12, R13, R14, R15,
  CPSR, CPSR_flg,
  SPSR, SPSR_flg,
  T, rVcs, rVds,         // virtual registers for code and data segments
  Racc0,                 // Intel xScale coprocessor accumulator
  FPSID, FPSCR, FPEXC,   // VFP system registers
  FPINST, FPINST2, MVFR0, MVFR1,
  // msr system registers
  SYSM_APSR,
  SYSM_IAPSR,
  SYSM_EAPSR,
  SYSM_XPSR,
  SYSM_IPSR,
  SYSM_EPSR,
  SYSM_IEPSR,
  SYSM_MSP,
  SYSM_PSP,
  SYSM_PRIMASK,
  SYSM_BASEPRI,
  SYSM_BASEPRI_MAX,
  SYSM_FAULTMASK,
  SYSM_CONTROL,
  Q0,  Q1,   Q2,  Q3,  Q4,  Q5,  Q6,  Q7,
  Q8,  Q9,  Q10, Q11, Q12, Q13, Q14, Q15,
  D0,  D1,   D2,  D3,  D4,  D5,  D6,  D7,
  D8,  D9,  D10, D11, D12, D13, D14, D15,
  D16, D17, D18, D19, D20, D21, D22, D23,
  D24, D25, D26, D27, D28, D29, D30, D31,
  S0,  S1,   S2,  S3,  S4,  S5,  S6,  S7,
  S8,  S9,  S10, S11, S12, S13, S14, S15,
  S16, S17, S18, S19, S20, S21, S22, S23,
  S24, S25, S26, S27, S28, S29, S30, S31,
  FIRST_FPREG=Q0,
  LAST_FPREG=S31,
  CF, ZF, NF, VF,

  // AArch64 registers
  // general-purpose registers
  X0,  X1,  X2,   X3,  X4,  X5,  X6,  X7,
  X8,  X9,  X10, X11, X12, X13, X14, X15,
  X16, X17, X18, X19, X20, X21, X22, X23,
  X24, X25, X26, X27, X28,
  X29, XFP = X29, // frame pointer
  X30, XLR = X30, // link register

  XZR, // zero register (special case of GPR=31)

  XSP, // stack pointer (special case of GPR=31)

  XPC, // PC (not available as actual register)

  // 128-bit SIMD registers
  V0,  V1,  V2,   V3,  V4,  V5,  V6,  V7,
  V8,  V9,  V10, V11, V12, V13, V14, V15,
  V16, V17, V18, V19, V20, V21, V22, V23,
  V24, V25, V26, V27, V28, V29, V30, V31,

  ARM_MAXREG,            // must be the last entry
};

// we use specflag1 to store register values
// so they must fit into a byte
CASSERT(ARM_MAXREG<0x100);

extern const char *arm_regnames[];

//------------------------------------------------------------------
//      r0         *    argument word/integer result
//      r1-r3           argument word
//
//      r4-r8        S  register variable
//      r9           S  (rfp) register variable (real frame pointer)
//
//      r10        F S  (sl) stack limit (used by -mapcs-stack-check)
//      r11        F S  (fp) argument pointer
//      r12             (ip) temp workspace
//      r13        F S  (sp) lower end of current stack frame
//      r14             (lr) link address/workspace
//      r15        F    (pc) program counter
//
//      f0              floating point result
//      f1-f3           floating point scratch
//
//      f4-f7        S  floating point variable

#define PC      R15
#define LR      R14
#define SP      R13
#define FP      R11
#define FP2     R7  // in thumb mode

inline int getreg(const op_t &x)
{
  return x.type == o_reg
      || x.type == o_shreg
       && x.shtype == LSL
       && x.shcnt == 0 ? x.reg : -1;
}

inline bool isreg(const op_t &x, int reg)
{
  return getreg(x) == reg;
}

// is it simply [Rx, Ry]?
// no shift, no negation, no post-index, no writeback
inline bool is_simple_phrase(const op_t &x)
{
  return x.type == o_phrase
      && x.shtype == LSL
      && x.shcnt == 0
      && (cmd.auxpref & (aux_negoff|aux_postidx|aux_wback)) == 0;
}

inline bool issp(const op_t &x) { return isreg(x, SP) || isreg(x, XSP); }
inline bool issp(int reg) { return reg == SP || reg == XSP; }

#define is_a64reg(reg) ((reg) >= X0 && (reg) < ARM_MAXREG)

//------------------------------------------------------------------
// PSR format:
//      bit     name    description
//      0       M0      M4..M0 are mode bits:
//      1       M1              10000   User
//      2       M2              10001   FIQ (fast interrupt request)
//      3       M3              10010   IRQ (interrupt request)
//      4       M4              10011   Supervisor
//                              10110   Monitor (security extensions)
//                              10111   Abort
//                              11010   Hyp (Hypervisor; virtualization extensions)
//                              11011   Undefined
//                              11111   System
//      5       T       Thumb state
//      6       F       FIQ disable
//      7       I       IRQ disable
//      8       A       Asynchronous abort disable
//      9       E       Endianness (0=little endian, 1=big endian)
//      10      IT2     IT7...IT0 If-Then execution state bits (ITSTATE)
//      11      IT3
//      12      IT4
//      13      IT5
//      14      IT6
//      15      IT7
//      16      GE0     GE3..GE0  Greater than or Equal flags (for SIMD instructions)
//      17      GE1
//      18      GE2
//      19      GE3
//      24      J       Jazelle state
//      25      IT0
//      26      IT1
//      27      Q       Cumulative saturation flag
//      28      V       Overflow
//      29      C       Carry/Borrow/Extend
//      30      Z       Zero
//      31      N       Negative/Less Than

enum arm_mode_t
{
  M_usr = B8(10000),
  M_fiq = B8(10001),
  M_irq = B8(10010),
  M_svc = B8(10011),
  M_mon = B8(10110),
  M_abt = B8(10111),
  M_hyp = B8(11010),
  M_und = B8(11011),
  M_sys = B8(11111),
};

//------------------------------------------------------------------
// Vector summary:
//      Address Exception               Mode on Entry
//      ------- ---------               -------------
//      0000    Reset                   Supervisor
//      0004    Undefined instruction   Undefined
//      0008    Software interrupt      Supervisor
//      000C    Abort (prefetch)        Abort
//      0010    Abort (data)            Abort
//      0014    Hypervisor trap         Hyp
//      0018    IRQ                     IRQ
//      001C    FIQ                     FIQ

//------------------------------------------------------------------
// Condition codes:
enum cond_t
{
  cEQ,          // 0000 Z                        Equal
  cNE,          // 0001 !Z                       Not equal
  cCS,          // 0010 C                        Unsigned higher or same
  cCC,          // 0011 !C                       Unsigned lower
  cMI,          // 0100 N                        Negative
  cPL,          // 0101 !N                       Positive or Zero
  cVS,          // 0110 V                        Overflow
  cVC,          // 0111 !V                       No overflow
  cHI,          // 1000 C & !Z                   Unsigned higher
  cLS,          // 1001 !C | Z                   Unsigned lower or same
  cGE,          // 1010 (N & V) | (!N & !V)      Greater or equal
  cLT,          // 1011 (N & !V) | (!N & V)      Less than
  cGT,          // 1100 !Z & ((N & V)|(!N & !V)) Greater than
  cLE,          // 1101 Z | (N & !V) | (!N & V)  Less than or equal
  cAL,          // 1110 Always
  cNV,          // 1111 Never
};

//------------------------------------------------------------------
extern netnode helper;      // altval(-1): idp flags
                            // altval(ea): callee address for indirect calls
#define DXREF_TAG    'd'    // altval(ea): resolved address for complex calculation (e.g. ADD R1, PC)
#define DELAY_TAG    'D'    // altval(ea) == 1: analyze ea for a possible offset
#define ITBLOCK_TAG  'I'    // altval(ea): packed it_info_t
#define FBASE_REG    'R'    // altval(ea): fbase register for function at ea
#define FBASE_VAL    'B'    // altval(ea): fbase value (usually GOT address) for function at ea
#define FPTR_REG     'F'    // altval(ea): frame pointer register (plus 1) for function at ea
#define FPTR_EA      'f'    // altval(ea): address where the fp register is set
#define FIXED_STKPNT 'x'    // charval(ea): may not modify sp value at this address
#define PUSHINFO_TAG 's'    // blob(ea): packed pushinfo_t
#define ARCHINFO_TAG 'a'    // blob(0): packed arm_arch_t

// fbase reg is a register used to access GOT in the current function
// it is usually R10
inline bool get_fbase_reg(ea_t ea, ushort *reg, ea_t *value)
{
  uval_t v = helper.altval(ea, FBASE_VAL);
  if ( v == 0 )
    return false;
  *reg = (ushort)helper.altval(ea, FBASE_REG);
  *value = v;
  return true;
}

inline void set_fbase_reg(ea_t ea, ushort reg, ea_t value)
{
  helper.altset(ea, reg, FBASE_REG);
  helper.altset(ea, value, FBASE_VAL);
}

// return register that is used as frame pointer for current function
// usually it's R11 or R7
inline ushort get_fptr_reg(ea_t func_ea)
{
  return ushort(helper.altval(func_ea, FPTR_REG) - 1);
}

inline void set_fptr_reg(ea_t func_ea, ushort reg)
{
  helper.altset(func_ea, reg+1, FPTR_REG);
}

// The address where the frame pointer register is set
inline ea_t get_fp_ea(ea_t func_ea)
{
  sval_t off = helper.altval(func_ea, FPTR_EA) - 1;
  if ( off != BADADDR )
    off += func_ea;
  return off;
}

inline void set_fp_ea(ea_t func_ea, ea_t insn_ea)
{
  helper.altset(func_ea, insn_ea+1-func_ea, FPTR_EA);
}

extern bool file_loaded;
extern ea_t got_ea;          // .got start address
extern ushort idpflags;

#define IDP_SIMPLIFY       0x0001
#define IDP_NO_PTR_DEREF   0x0002
#define IDP_MACRO          0x0004
#define IDP_ARM5           0x0008
#define IDP_NO_SETSGR      0x0010
#define IDP_NO_BL_JUMPS    0x0020

inline bool simplify(void)    { return (idpflags & IDP_SIMPLIFY) != 0; }
inline bool deref_ptrs(void)  { return (idpflags & IDP_NO_PTR_DEREF) == 0; }
inline bool macro(void)       { return (idpflags & IDP_MACRO) != 0; }
inline bool may_setsgr(void)  { return (idpflags & IDP_NO_SETSGR) == 0; }
inline bool no_bl_jumps(void) { return (idpflags & IDP_NO_BL_JUMPS) != 0; }

//----------------------------------------------------------------------
// see ARMExpandImm_C/ThumbExpandImm_C in ARM ARM
inline bool may_set_carry(ushort itype)
{
  switch ( itype )
  {
    case ARM_and:
    case ARM_bic:
    case ARM_eor:
    case ARM_mov:
    case ARM_mvn:
    case ARM_orn:
    case ARM_orr:
    case ARM_teq:
    case ARM_tst:
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
// if true, then ASPR.C is set to bit 31 of the immediate constant
inline bool imm_sets_carry(const insn_t &ins)
{
  switch ( ins.itype )
  {
    case ARM_and:
    case ARM_bic:
    case ARM_eor:
    case ARM_mov:
    case ARM_mvn:
    case ARM_orn:
    case ARM_orr:
      // flags are updated if S suffix is used
      return (ins.auxpref & (aux_immcarry|aux_cond)) == (aux_immcarry|aux_cond);
    case ARM_teq:
    case ARM_tst:
      // these two always update flags
      return (ins.auxpref & aux_immcarry) != 0;
  }
  return false;
}

//----------------------------------------------------------------------
inline bool is_thumb_ea(ea_t ea)
{
  if ( !has_arm() )
    return true;
  sel_t t = get_segreg(ea, T);
  return t != BADSEL && t != 0;
}

//----------------------------------------------------------------------
inline bool is_arm64_ea(ea_t ea)
{
#ifndef __EA64__
  qnotused(ea);
  return false;
#else
  segment_t *seg = getseg(ea);
  return seg != NULL && seg->use64();
#endif
}

//----------------------------------------------------------------------
struct pushreg_t
{
  ea_t ea;              // instruction ea
  uval_t off;           // offset from the frame top (sp delta)
  uval_t width;         // size of allocated area in bytes
  int reg;              // register number (-1 means stack space allocation)
  bool spoiled;         // is register spoiled?
};
typedef qvector<pushreg_t> pushregs_t;

struct pushinfo_t : public pushregs_t
{
  enum { PUSHINFO_VERSION = 1 };
  uint32 flags;
#define APSI_VARARG     0x01      // is vararg function?
#define APSI_FIRST_VARG_MASK 0x06 // index of the first register in push {rx..r3}
  inline int get_first_vararg_reg(void) { return (flags & APSI_FIRST_VARG_MASK) >> 1; }
  uval_t savedregs;     // size of the 'saved regs' area
  eavec_t prolog_insns; // additional prolog instruction addresses
                        // (in addition to instructions from pushregs_t)
  uval_t fpd;           // frame pointer delta

  pushinfo_t(void) : flags(0), savedregs(0), fpd(0) {}
  void save_to_idb(ea_t ea);
  bool restore_from_idb(ea_t ea);
};

//----------------------------------------------------------------------
// The following events are supported by the ARM module in the ph.notify() function
namespace arm_module_t
{
  enum event_codes_t
  {
    set_thumb_mode = processor_t::loader,
                        // switch to thumb mode
                        // in: ea_t ea
    set_arm_mode,       // switch to arm mode
                        // in: ea_t ea
    restore_pushinfo,   // Restore function prolog info from the database
                        // in: ea_t func_start
                        //     pushinfo_t *pi
                        // Returns: 2-ok, otherwise-failed
    save_pushinfo,      // Save function prolog info to the database
                        // in: ea_t func_start
                        //     pushinfo_t *pi
                        // Returns: 2-ok, otherwise-failed
    is_push_insn,       // Is push instruction?
                        // in: uint32 *reglist
                        // cmd struct is filled
                        // Returns: 2-yes, -1-no
    is_pop_insn,        // Is pop instruction?
                        // in: uint32 *reglist
                        //     bool allow_ldmed
                        // cmd struct is filled
                        // Returns: 2-yes, -1-no
    is_gnu_mcount_nc,   // Is __gnu_mcount_nc function?
  };
}

//------------------------------------------------------------------
void init_ana(void);
void term_ana(void);
void add_it_block(ea_t ea);
void del_insn_info(ea_t ea);
int get_it_size(void);
void idaapi header(void);
void idaapi footer(void);

void idaapi assumes(ea_t ea);
void idaapi segstart(ea_t ea);
void idaapi segend(ea_t ea);

extern int mnem_width;
extern int cfh_pg21_id;
extern int cfh_lo12_id;

void idaapi out(void);
bool idaapi outspec(ea_t ea,uchar segtype);

int idaapi ana(void);
int ana_arm(void);
int ana_thumb(void);
uint64 expand_imm_vfp(uint8 imm8, int sz);
int idaapi emu(void);
bool idaapi outop(op_t &op);
int idaapi is_align_insn(ea_t ea);

int may_be_func(void);
int is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *function_pointer);
int is_arm_sane_insn(int asn_flags);
#define ASN_NOCREFS    0x01 // there are no crefs to the insn
#define ASN_THUMB      0x02 // use thumb mode
#define ASN_CHECK_MODE 0x04 // check thumb/arm mode of the next insn
bool is_call_insn(void);
bool is_return_insn(bool only_lr = false);
bool is_push_insn(uint32 *reglist=NULL);
bool is_pop_insn(uint32 *reglist=NULL, bool allow_ed=false);
int arm_create_switch_xrefs(ea_t insn_ea, const switch_info_ex_t &si);
void mark_arm_codeseqs(void);
void destroy_macro_with_internal_cref(ea_t to);
void arm_erase_info(ea_t ea1, ea_t ea2);
void arm_move_segm(ea_t from, const segment_t *s);
#if defined(NALT_HPP) && defined(_XREF_HPP)
int arm_calc_switch_cases(ea_t insn_ea, const switch_info_ex_t *si, casevec_t *casevec, eavec_t *targets);
#endif

int  idaapi sp_based(const op_t &x);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi arm_get_frame_retsize(func_t *pfn);
bool copy_insn_optype(op_t &x, ea_t ea, void *value = NULL, bool force = false);

int get_arm_fastcall_regs(const int **regs);
bool calc_arm_arglocs(func_type_data_t *fti);
bool calc_arm_varglocs(
        func_type_data_t *fti,
        regobjs_t *regargs,
        int nfixed);
bool calc_arm_retloc(const tinfo_t &tif, cm_t cc, argloc_t *retloc);
int use_arm_regarg_type(ea_t ea, const funcargvec_t &rargs);
void use_arm_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);

//----------------------------------------------------------------------
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

bool arm_get_operand_info(ea_t ea,
                          int n,
                          int tid,
                          getreg_t *getreg,
                          const regval_t *rv,
                          idd_opinfo_t *opinf);
ea_t arm_next_exec_insn(ea_t ea,
                         int tid,
                         getreg_t *getreg,
                         const regval_t *regvalues);
ea_t arm_calc_step_over(ea_t ip);
int arm_calc_next_eas(bool over, ea_t *res, int *nsubs);
ea_t arm_get_macro_insn_head(ea_t ip);
int arm_get_dbr_opnum(ea_t ea);
ssize_t arm_get_reg_name(int _reg, size_t width, char *buf, size_t bufsize, int reghi);
ssize_t arm_get_one_reg_name(int _reg, size_t width, char *outbuf, size_t bufsize);
int arm_get_reg_index(const char *name, bitrange_t *pbitrange);
const char *arm_get_reg_info(const char *name, bitrange_t *pbitrange);
bool try_code_start(ea_t ea, bool respect_low_bit);
int try_offset(ea_t ea);
bool ana_neon(uint32 code, bool thumb);
void opimm_vfp(op_t &x, uint32 imm8, int sz);
void check_displ(op_t &x, bool alignPC = false);
void set_gotea(ea_t ea);
bool is_gnu_mcount_nc(ea_t ea);
bool verify_sp(func_t *pfn);
bool equal_ops(const op_t &x, const op_t &y);

#pragma pack(pop)
#endif // _ARM_HPP
