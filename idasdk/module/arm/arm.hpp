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
#include <segregs.hpp>
#include <typeinf.hpp>

#include <set>

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

struct arm_arch_t;
extern arm_arch_t arch;

//---------------------------------

#define dt_half         0x7f  // special value for op_t.dtype for half-precision registers
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

//-------------------------------------------------------------------------
// we will store the suffix in insnpref, since it's used only by the IT instruction
// if we need two suffixes (VCVTxx), we'll store the second one in Op1.specflag1
inline void set_neon_suffix(insn_t &insn, neon_datatype_t suf1, neon_datatype_t suf2 = DT_NONE)
{
  if ( suf1 != DT_NONE )
  {
    insn.insnpref = char(0x80 | suf1);
    if ( suf2 != DT_NONE )
      insn.Op1.specflag1 = suf2;
  }
}

//-------------------------------------------------------------------------
inline neon_datatype_t get_neon_suffix(const insn_t &insn)
{
  if ( insn.insnpref & 0x80 )
    return neon_datatype_t(insn.insnpref & 0x7F);
  else
    return DT_NONE;
}

//-------------------------------------------------------------------------
inline neon_datatype_t get_neon_suffix2(const insn_t &insn)
{
  return neon_datatype_t(insn.Op1.specflag1);
}

//----------------------------------------------------------------------
inline char dtype_from_dt(neon_datatype_t dt)
{
  switch ( dt )
  {
    case DT_8:
    case DT_S8:
    case DT_U8:
    case DT_I8:
    case DT_P8:
      return dt_byte;
    case DT_16:
    case DT_S16:
    case DT_U16:
    case DT_I16:
    case DT_P16:
      return dt_word;
    case DT_32:
    case DT_S32:
    case DT_U32:
    case DT_I32:
      return dt_dword;
    case DT_64:
    case DT_S64:
    case DT_U64:
    case DT_I64:
    case DT_NONE:
    default:
      return dt_qword;
    case DT_F16:
      return dt_half;
    case DT_F32:
      return dt_float;
    case DT_F64:
      return dt_double;
  }
}

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
                                           // 0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits, 5=128 bits)
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

#define dt_half         0x7f  // special value for op_t.dtype for half-precision registers
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

int bitcount(uint32 x);

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
CASSERT(ARM_MAXREG < 0x100);

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
inline bool is_simple_phrase(const insn_t &insn, const op_t &x)
{
  return x.type == o_phrase
      && x.shtype == LSL
      && x.shcnt == 0
      && (insn.auxpref & (aux_negoff|aux_postidx|aux_wback)) == 0;
}

inline bool issp(const op_t &x) { return isreg(x, SP) || isreg(x, XSP); }
inline bool issp(int reg) { return reg == SP || reg == XSP; }

#define is_a64reg(reg) ((reg) >= X0 && (reg) < ARM_MAXREG)

inline bool is_gr(int reg)
{
  return reg >= R0 && reg <= R14
      || reg >= X0 && reg <= X30;
}

// is callee-saved (preserved) register? (according to Procedure Call Standard)
/* Procedure Call Standard for the ARM Architecture:
5.1.1. A subroutine must preserve the contents of the registers r4-r8,
r10, r11 and SP (and r9 in PCS variants that designate r9 as v6).
Procedure Call Standard for the ARM 64-bit Architecture:
5.1.1. A subroutine invocation must preserve the contents of the
registers r19-r29 and SP.
*/
inline bool is_callee_saved_gr(int reg)
{
  return reg >= R4  && reg <= R11
      || reg >= X19 && reg <= X29;
}
/* Procedure Call Standard for the ARM Architecture:
5.1.2.1 Registers s16-s31 (d8-d15, q4-q7) must be preserved across
subroutine calls; registers s0-s15 (d0-d7, q0-q3) do not need to be
preserved (and can be used for passing arguments or returning results in
standard procedure-call variants)
Procedure Call Standard for the ARM 64-bit Architecture:
5.1.2. Registers v8-v15 must be preserved by a callee across subroutine
calls.
*/
inline bool is_callee_saved_vr(int reg)
{
  return reg >= S16 && reg <= S31
      || reg >= D8  && reg <= D15
      || reg >= Q4  && reg <= Q7
      || reg >= V8  && reg <= V15;
}

//----------------------------------------------------------------------
// get full value of the immediate operand
// (performing optional shift operator)
inline uval_t get_immfull(const op_t &x)
{
  // FIXME support other types of shift
  return x.type != o_imm  ? 0
       : x.value == 0     ? 0
       : x.ishcnt == 0    ? x.value
       : x.ishtype == LSL ? x.value << x.ishcnt
       : x.ishtype == MSL ? ((x.value + 1) << x.ishcnt) - 1
       :                    0;
}
//----------------------------------------------------------------------
// check if 'reg' is present in 'reglist' (only ARM32 GPRs supported!)
inline bool in_reglist(uint32 reglist, int reg)
{
  return (reg <= R15) && (reglist & (1u << reg)) != 0;
}
//----------------------------------------------------------------------
// calculate the total number of bytes represented by a register list
inline uval_t calc_reglist_size(uint32 reglist)
{
  return uval_t(4) * bitcount(reglist & 0xFFFF);
}

//----------------------------------------------------------------------
// Is register 'reg' spoiled by the current instruction?
// If flag <use_pcs> is set then it is assumed that call instruction
// doesn't spoil callee-saved registers (according to Procedure Call
// Standard the are r4-r8, r10, r11, SP for AArch32, r19-r29, SP for
// AArch64). If this flag is not set then this function assumes that
// call instruction spoils LR and r0 (why?).
bool spoils(const insn_t &insn, int reg, bool use_pcs = false);
// If flag <use_pcs> is set then it is assumed that call instruction
// doesn't spoil callee-saved registers else this function assumes that
// call instruction spoils everything (why?).
int  spoils(const insn_t &insn, const uint32 *regs, int n, bool use_pcs = false);
// is PSR (Program Status Register) spoiled by the instruction ?
bool spoils_psr(const insn_t &insn);

//----------------------------------------------------------------------
// find out pre- or post-indexed addressing mode of given operand <op>;
// if <delta> arg is specified than we check o_displ operand only and
// return register offset in <delta>;
// returns base register or -1
inline int get_pre_post_delta(const insn_t &insn, const op_t &op, sval_t *delta = NULL)
{
  if ( (insn.auxpref & (aux_wback | aux_postidx)) != 0
    && (op.type == o_displ && op.addr != 0
     || op.type == o_phrase && delta == NULL) )
  {
    if ( delta )
      *delta = op.addr;
    return op.reg;
  }
  return -1;
}

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
  cLAST
};
inline cond_t invert_cond(cond_t cond)
{
  if ( cond < cLAST )
    return cond_t(cond ^ 1);
  return cLAST;
}

//------------------------------------------------------------------
extern netnode helper;      // altval(-1): idp flags
#define CALLEE_TAG   'A'    // altval(ea): callee address for indirect calls
#define DXREF_TAG    'd'    // altval(ea): resolved address for complex calculation (e.g. ADD R1, PC)
#define DELAY_TAG    'D'    // altval(ea) == 1: analyze ea for a possible offset
#define ITBLOCK_TAG  'I'    // altval(ea): packed it_info_t
#define FPTR_REG_TAG 'F'    // supval(ea): frame pointer info fptr_info_t
#define FIXED_STKPNT 'x'    // charval(ea): may not modify sp value at this address
#define PUSHINFO_TAG 's'    // blob(ea): packed pushinfo_t
#define ARCHINFO_TAG 'a'    // blob(0): packed arm_arch_t

inline void set_callee(ea_t ea, ea_t callee) { helper.easet(ea, callee, CALLEE_TAG); }
inline ea_t get_callee(ea_t ea) { return helper.eaget(ea, CALLEE_TAG); }
inline void del_callee(ea_t ea) { helper.eadel(ea, CALLEE_TAG); }

inline void set_dxref(ea_t ea, ea_t dxref) { helper.easet(ea, dxref, DXREF_TAG); }
inline ea_t get_dxref(ea_t ea) { return helper.eaget(ea, DXREF_TAG); }
inline void del_dxref(ea_t ea) { helper.eadel(ea, DXREF_TAG); }

struct fptr_info_t
{
  ea_t addr;   // address where the fp register is set
  ushort reg;  // frame pointer for current function (usually R11 or R7)
};

void set_fptr_info(ea_t func_ea, ushort reg, ea_t addr);
bool get_fptr_info(fptr_info_t *fpi, ea_t func_ea);
inline ushort get_fptr_reg(ea_t func_ea)
{
  fptr_info_t fpi;
  return get_fptr_info(&fpi, func_ea) ? fpi.reg : ushort(-1);
}

inline ea_t get_fp_ea(ea_t func_ea)
{
  fptr_info_t fpi;
  return get_fptr_info(&fpi, func_ea) ? fpi.addr : BADADDR;
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
inline bool imm_sets_carry(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case ARM_and:
    case ARM_bic:
    case ARM_eor:
    case ARM_mov:
    case ARM_mvn:
    case ARM_orn:
    case ARM_orr:
      // flags are updated if S suffix is used
      return (insn.auxpref & (aux_immcarry|aux_cond)) == (aux_immcarry|aux_cond);
    case ARM_teq:
    case ARM_tst:
      // these two always update flags
      return (insn.auxpref & aux_immcarry) != 0;
  }
  return false;
}

inline bool has_arm();

//----------------------------------------------------------------------
inline bool is_thumb_ea(ea_t ea)
{
  if ( !has_arm() )
    return true;
  sel_t t = get_sreg(ea, T);
  return t != BADSEL && t != 0;
}

//----------------------------------------------------------------------
inline bool is_arm64_ea(ea_t ea)
{
#if !defined(__EA64__)
  qnotused(ea);
  return false;
#elif defined(__LINUX__) && defined(__ARM__)    // android_server64
  qnotused(ea);
  return true;
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
};
typedef qvector<pushreg_t> pushregs_t;

struct pushinfo_t : public pushregs_t
{
  enum { PUSHINFO_VERSION = 2 };
  uint32 flags;
#define APSI_VARARG     0x01      // is vararg function?
#define APSI_FIRST_VARG_MASK 0x06 // index of the first register in push {rx..r3}
#define APSI_HAVE_SSIZE 0x08      // pushinfo_t structure contains its own size (field 'cb')
#define APSI_OFFSET_WO_DELTA 0x10 // do not use delta-coding for <off>
  inline int get_first_vararg_reg(void) { return (flags & APSI_FIRST_VARG_MASK) >> 1; }
  uval_t savedregs;     // size of the 'saved regs' area
  eavec_t prolog_insns; // additional prolog instruction addresses
                        // (in addition to instructions from pushregs_t)
  uval_t fpd;           // frame pointer delta

  int cb;               // size of this structure (it would be better if
                        // this field was the first one)

  // vararg info
  uval_t gr_top;        // offset from the frame top general registers
                        // vararg save area
  uval_t vr_top;        // offset from the frame top FP/SIMD registers
                        // vararg save area
  uval_t gr_width;      // size of general registers vararg save area
  uval_t vr_width;      // size of FP/SIMD registers vararg save area

  pushinfo_t(void)
    : flags(APSI_HAVE_SSIZE),
      savedregs(0), fpd(0),
      cb(sizeof(pushinfo_t)),
      gr_top(0), vr_top(0), gr_width(0), vr_width(0)
  {}

  void save_to_idb(ea_t ea);
  bool restore_from_idb(ea_t ea);

  //--------------------------------------------------------------------
  void mark_prolog_insns(void)
  {
    for ( int i=0; i < size(); i++ )
      mark_prolog_insn(at(i).ea);
    for ( int i=0; i < prolog_insns.size(); i++ )
      mark_prolog_insn(prolog_insns[i]);
  }
};

//----------------------------------------------------------------------
enum arm_base_arch_t
{
  // values taken from ARM IHI 0045C, Tag_CPU_arch
  arch_ARM_old  = 0,    // Pre-v4
  arch_ARMv4    = 1,    // e.g. SA110
  arch_ARMv4T   = 2,    // e.g. ARM7TDMI
  arch_ARMv5T   = 3,    // e.g. ARM9TDMI
  arch_ARMv5TE  = 4,    // e.g. ARM946E-S
  arch_ARMv5TEJ = 5,    // e.g. ARM926EJ-S
  arch_ARMv6    = 6,    // e.g. ARM1136J-S
  arch_ARMv6KZ  = 7,    // e.g. ARM1176JZ-S
  arch_ARMv6T2  = 8,    // e.g. ARM1156T2F-S
  arch_ARMv6K   = 9,    // e.g. ARM1136J-S
  arch_ARMv7    = 10,   // e.g. Cortex A8, Cortex M3
  arch_ARMv6M   = 11,   // e.g. Cortex M1
  arch_ARMv6SM  = 12,   // v6-M with the System extensions
  arch_ARMv7EM  = 13,   // v7-M with DSP extensions
  arch_ARMv8    = 14,   // v8
  arch_curr_max = arch_ARMv8,
  arch_ARM_meta = 9999, // decode everything
};

enum arm_arch_profile_t
{
  arch_profile_unkn = 0, // Architecture profile is not applicable (e.g. pre v7, or cross-profile code)
  arch_profile_A = 'A',  // The application profile (e.g. for Cortex A8)
  arch_profile_R = 'R',  // The real-time profile (e.g. for Cortex R4)
  arch_profile_M = 'M',  // The microcontroller profile (e.g. for Cortex M3)
  arch_profile_S = 'S',  // Application or real-time profile (i.e. the 'classic' programmer's model)
};

enum fp_arch_t
{
  fp_arch_none  = 0, // The user did not permit this entity to use instructions requiring FP hardware
  fp_arch_v1    = 1, // The user permitted use of instructions from v1 of the floating point (FP) ISA
  fp_arch_v2    = 2, // Use of the v2 FP ISA was permitted (implies use of the v1 FP ISA)
  fp_arch_v3    = 3, // Use of the v3 FP ISA was permitted (implies use of the v2 FP ISA)
  fp_arch_v3_16 = 4, // Use of the v3 FP ISA was permitted, but only citing registers D0-D15, S0-S31
  fp_arch_v4    = 5, // Use of the v4 FP ISA was permitted (implies use of the non-vector v3 FP ISA)
  fp_arch_v4_16 = 6, // Use of the v4 FP ISA was permitted, but only citing registers D0-D15, S0-S31
  fp_arch_v8    = 7, // Use of the ARM v8-A FP ISA was permitted
  fp_arch_v8_16 = 8, // Use of the ARM v8-A FP ISA was permitted, but only citing registers D0-D15, S0-S31
};

enum adv_simd_arch_t
{
  adv_simd_arch_none = 0, // The user did not permit this entity to use the Advanced SIMD Architecture (Neon)
  adv_simd_arch_base = 1, // Use of the Advanced SIMD Architecture (Neon) was permitted
  adv_simd_arch_fma  = 2, // Use of Advanced SIMD Architecture (Neon) with fused MAC operations was permitted
  adv_simd_arch_v8   = 3, // Use of the ARM v8-A Advanced SIMD Architecture (Neon) was permitted
};

struct arm_arch_t
{
  arm_base_arch_t base_arch;
  arm_arch_profile_t profile;
  fp_arch_t fp_arch;
  adv_simd_arch_t neon_arch;

  int arm_isa_use;   // 0 = no ARM instructions (e.g. v7-M)
                     // 1 = allow ARM instructions
  int thumb_isa_use; // 0 = no Thumb instructions
                     // 1 = 16-bit Thumb instructions + BL
                     // 2 = plus 32-bit Thumb instructions
  int xscale_arch;   // 0 = no XScale extension
                     // 1 = XScale extension (MAR/MRA etc)
  int wmmx_arch;     // 0 = no WMMX
                     // 1 = WMMX v1
                     // 2 = WMMX v2
  int hp_ext;        // 0 = no half-precision extension
                     // 1 = VFPv3/Advanced SIMD optional half-precision extension
  int t2_ee;         // 0 = no Thumb2-EE extension
                     // 1 = Thumb2-EE extension (ENTERX and LEAVEX)
  qstring arch_name; // e.g. ARMv7-M
  qstring core_name; // e.g. ARM1176JZF-S

  bool be8;          // image is BE-8, i.e. little-endian code but big-endian data

  static const char *get_canonical_name(int archno);
  bool set_from_name(const char *name); // arch name or core name
  bool set_options(const char *opts); // semicolon-delimited option string
  void save_to_idb() const;
  bool restore_from_idb();
  qstring to_string() const;
  arm_arch_t(void) { memset(this, 0, sizeof(*this)); }

  bool is_mprofile()
  {
    if ( profile == arch_profile_unkn )
    {
      return base_arch >= arch_ARMv6M && base_arch <= arch_ARMv7EM;
    }
    return profile == arch_profile_M;
  }
};

extern arm_arch_t arch;

inline bool has_arm()    { return arch.arm_isa_use != 0; }
inline bool has_thumb()  { return arch.thumb_isa_use != 0; }
inline bool has_thumb2() { return arch.thumb_isa_use >= 2; }
inline bool has_xscale() { return arch.xscale_arch != 0; }
inline bool has_vfp()    { return arch.fp_arch != fp_arch_none; }
inline bool has_neon()   { return arch.neon_arch != adv_simd_arch_none; }
#ifndef ENABLE_LOWCNDS
inline bool has_armv5()  { return arch.base_arch >= arch_ARMv5T; }
inline bool has_armv7a() { return arch.base_arch == arch_ARMv7 || arch.base_arch > arch_ARMv7EM; }
inline bool has_armv8()  { return arch.base_arch >= arch_ARMv8; }
inline bool is_mprofile() { return arch.is_mprofile(); }
#endif
inline bool is_be8()     { return arch.be8 != 0; }

//------------------------------------------------------------------
struct mmtype_t
{
  const char *name;
  const type_t *type;
  const type_t *fields;
  tinfo_t tif;
};

//------------------------------------------------------------------
void init_ana(void);
void term_ana(void);
void move_it_blocks(ea_t from, ea_t to, asize_t size);
void add_it_block(const insn_t &insn);
void del_insn_info(ea_t ea);
int get_it_size(const insn_t &insn);
void idaapi header(outctx_t &ctx);
void idaapi footer(outctx_t &ctx);

void idaapi assumes(outctx_t &ctx);
void idaapi segstart(outctx_t &ctx, segment_t *seg);
void idaapi segend(outctx_t &ctx, segment_t *seg);

extern int mnem_width;
extern int ref_pg21_id;
extern int ref_lo12_id;

bool idaapi outspec(outctx_t &ctx, uchar segtype);

int idaapi ana(insn_t *out);
int ana_arm(insn_t &insn);
int ana64(insn_t &insn);
int ana_thumb(insn_t &insn);
bool ana_coproc(insn_t &insn, uint32 code);
uint64 expand_imm_vfp(uint8 imm8, int sz);
int idaapi emu(const insn_t &insn);
int idaapi is_align_insn(ea_t ea);
bool idaapi equal_ops(const op_t &x, const op_t &y);

int may_be_func(const insn_t &insn);
int is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *function_pointer);
int is_arm_sane_insn(const insn_t &insn, int asn_flags);
#define ASN_NOCREFS    0x01 // there are no crefs to the insn
#define ASN_THUMB      0x02 // use thumb mode
#define ASN_CHECK_MODE 0x04 // check thumb/arm mode of the next insn
bool is_arm_call_insn(const insn_t &insn);
bool is_return_insn(const insn_t &insn, bool only_lr = false);
bool is_branch_insn(const insn_t &insn);
bool is_push_insn(const insn_t &insn, uint32 *reglist=NULL);
bool is_pop_insn(const insn_t &insn, uint32 *reglist=NULL, bool allow_ed=false);
int arm_create_switch_xrefs(ea_t insn_ea, const switch_info_t &si);
void mark_arm_codeseqs(void);
void destroy_macro_with_internal_cref(ea_t to);
void arm_erase_info(ea_t ea1, ea_t ea2);
void arm_move_segm(ea_t from, const segment_t *s, bool changed_netmap);
bool can_resolve_seg(ea_t ea);
#if defined(NALT_HPP) && defined(_XREF_HPP)
int arm_calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si);
#endif

int  idaapi sp_based(const insn_t &insn, const op_t &x);
bool idaapi create_func_frame(func_t *pfn);
bool create_func_frame32(func_t *pfn);
bool create_func_frame64(func_t *pfn);
int  idaapi arm_get_frame_retsize(const func_t *pfn);
bool copy_insn_optype(const insn_t &insn, const op_t &x, ea_t ea, void *value = NULL, bool force = false);

bool get_arm_callregs(callregs_t *callregs, cm_t cc);
bool calc_arm_arglocs(func_type_data_t *fti);
bool calc_arm_varglocs(func_type_data_t *fti, regobjs_t *regargs, int nfixed);
bool calc_arm_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc);
bool adjust_arm_argloc(argloc_t *argloc, const tinfo_t *tif, int size);
void arm_lower_func_arg_types(intvec_t *argnums, const func_type_data_t &fti);
int use_arm_regarg_type(ea_t ea, const funcargvec_t &rargs);
void use_arm_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);
void term_arm_simdtypes(void);
int get_arm_simd_types(
        simd_info_vec_t *outtypes,
        const simd_info_t *pattern,
        const argloc_t *argloc,
        bool do_create);

//----------------------------------------------------------------------
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

bool arm_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        int tid,
        getreg_t *getreg,
        const regval_t *rv);
ea_t arm_next_exec_insn(
        ea_t ea,
        int tid,
        getreg_t *getreg,
        const regval_t *regvalues);
ea_t arm_calc_step_over(ea_t ip);
int arm_calc_next_eas(eavec_t *res, const insn_t &insn, bool over);
ea_t arm_get_macro_insn_head(ea_t ip);
int arm_get_dbr_opnum(const insn_t &insn);
ssize_t arm_get_reg_name(qstring *buf, int _reg, size_t width, int reghi);
ssize_t arm_get_one_reg_name(qstring *buf, int _reg, size_t width);
int arm_get_reg_index(const char *name, bitrange_t *pbitrange);
bool arm_get_reg_info(const char **main_name, bitrange_t *pbitrange, const char *name);
bool try_code_start(ea_t ea, bool respect_low_bit);
int try_offset(ea_t ea);
bool ana_neon(insn_t &insn, uint32 code, bool thumb);
void opimm_vfp(op_t &x, uint32 imm8, int sz);
void check_displ(const insn_t &insn, op_t &x, bool alignPC = false);
void arm_set_gotea(ea_t ea);
bool verify_sp(func_t *pfn);
void ana_hint(insn_t &insn, int hint);
char get_it_info(ea_t ea);

//======================================================================
// common inline functions used by analyzer
//----------------------------------------------------------------------
inline int bitcount(int x)
{
  int cnt = 0;
  while ( x )
  {
    x &= x - 1;
    cnt++;
  }
  return cnt;
}

//----------------------------------------------------------------------
inline void oreglist(op_t &x, int regs)
{
  x.type = o_reglist;
  x.dtype = dt_dword;
  x.reglist = regs;
}

//----------------------------------------------------------------------
inline void onear(op_t &x, uval_t target)
{
  x.type = o_near;
  x.dtype = dt_code;
  x.addr = target;
}

//----------------------------------------------------------------------
inline void otext(op_t &x, const char *txt)
{
  x.type = o_text;
  qstrncpy((char *)&x.value, txt, sizeof(x) - qoffsetof(op_t, value));
}

//----------------------------------------------------------------------
// Get register number
inline uchar getreg(uint32 code, int lbit)
{
  return uchar((code >> lbit) & 0xF);
}

//----------------------------------------------------------------------
// Create operand of register type
inline void fillreg(op_t &x, uint32 code, int lbit)
{
  x.reg = getreg(code, lbit);
  x.type = o_reg;
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
inline void opreg(op_t &x, int rgnum)
{
  x.reg = uint16(rgnum);
  x.type = o_reg;
  x.dtype = dt_dword;
}

struct reg_mode_t
{
  uint16 reg;
  uchar mode;
};

//----------------------------------------------------------------------
// Create operand of banked_reg type
extern const reg_mode_t banked0[32];
extern const reg_mode_t banked1[32];
inline bool opbanked(op_t &x, int R, uchar sysm)
{
  const reg_mode_t &rm = R ? banked1[sysm] : banked0[sysm];
  if ( rm.reg == 0xFFFF )
    return false;
  x.reg = rm.reg;
  x.specflag1 = rm.mode | BANKED_MODE;
  x.type = o_reg;
  x.dtype = dt_dword;
  return true;
}

//----------------------------------------------------------------------
// Create operand of immediate type
inline void op_imm(op_t &x, uval_t value)
{
  x.type = o_imm;
  x.dtype = dt_dword;
  x.value = value;
  x.ishtype = LSL;
  x.ishcnt = 0;
}

//----------------------------------------------------------------------
// Create operand of immediate type (4 bits)
inline void op_imm4(op_t &x, uint32 code, int lbit)
{
  op_imm(x, getreg(code, lbit));
}

//----------------------------------------------------------------------
inline void barrier_op(op_t &x, int code)
{
  const char *op = NULL;
  switch ( code )
  {
    case B8(0001): op = "OSHLD"; break;
    case B8(0010): op = "OSHST"; break;
    case B8(0011): op = "OSH";   break;
    case B8(0101): op = "NSHLD"; break;
    case B8(0110): op = "NSHST"; break;
    case B8(0111): op = "NSH";   break;
    case B8(1001): op = "ISHLD"; break;
    case B8(1010): op = "ISHST"; break;
    case B8(1011): op = "ISH";   break;
    case B8(1101): op = "LD";    break;
    case B8(1110): op = "ST";    break;
    case B8(1111): op = "SY";    break;
  }
  if ( op != NULL )
    otext(x, op);
  else
    op_imm(x, code & 0xF);
}

// is the current insn inside an it-block?
inline bool inside_itblock(char itcnd)
{
  return itcnd != -1;
}

//======================================================================
// common data sructures and functions for emulator
//----------------------------------------------------------------------

// since these is a lot of recursion in this module, we will keep
// all data as local as possible. no static data since we will have
// to save/restore it a lot
struct arm_saver_t
{
  insn_t insn; // current instruction
  bool flow;

  arm_saver_t() : insn(), flow(true) {}
  arm_saver_t(const insn_t &insn_) : insn(insn_), flow(true) {}

  void handle_operand(const op_t &x, bool isload);
  void emulate(void);
  void handle_code_ref(const op_t &x, ea_t ea, bool iscall);
  bool detect_glue_code(
          ea_t ea,
          int flags,
#define DGC_HANDLE 0x0001  // create offsets and names
#define DGC_FIND   0x0002  // ea points to the end of the glue code
          ea_t *p_target = NULL,
          ea_t *p_fptr = NULL,
          size_t *p_glue_size = NULL);
  bool detect_glue_code(
          int flags,
          ea_t *p_target = NULL,
          ea_t *p_fptr = NULL,
          size_t *p_glue_size = NULL);
  bool arm_is_switch(void);
  // this is a copy of the function from u_ana.cpp
  void clean_insn(ea_t ea, ea_t cs, ea_t ip)
  {
    memset(&insn, 0, sizeof(insn));
    insn.ea = ea;
    insn.cs = cs;
    insn.ip = ip;
    insn.Op1.flags = OF_SHOW;
    insn.Op2.flags = OF_SHOW;
    insn.Op3.flags = OF_SHOW;
    insn.Op4.flags = OF_SHOW;
    insn.Op5.flags = OF_SHOW;
    insn.Op6.flags = OF_SHOW;
    insn.Op2.n = 1;
    insn.Op3.n = 2;
    insn.Op4.n = 3;
    insn.Op5.n = 4;
    insn.Op6.n = 5;
  }
  // try to decode instruction at ea as arm or thumb
  //-V:try_decode:501 identical sub-expressions
  bool try_decode(ea_t ea, bool is_thumb, bool check_sane = true)
  {
    segment_t *s = getseg(ea);
    if ( s == NULL )
      return false;
    uval_t cs = get_segm_para(s);
    uval_t ip = ea - to_ea(cs, 0);
    clean_insn(ea, cs, ip);
    int sz = is_thumb ? ana_thumb(insn) : ana_arm(insn);
    int asn_flags = ASN_NOCREFS;
    if ( is_thumb )
      asn_flags |= ASN_THUMB;
    return sz > 0 && (!check_sane || is_arm_sane_insn(insn, asn_flags));
  }
};

// SPD value for security_push_cookie/security_pop_cookie
inline sval_t security_cookie_spd()
{
  return inf.is_64bit() ? 0x10 : 0x4;
}

// SPD value for a special function
inline sval_t special_func_spd(special_func_t spf)
{
  return spf == SPF_GNU_MCOUNT_NC        ? 4
       : spf == SPF_SECURITY_POP_COOKIE  ? security_cookie_spd()
       : spf == SPF_SECURITY_PUSH_COOKIE ? -security_cookie_spd()
       :                                   0;
}

int calc_fpreglist_size(const insn_t &ins);
int calc_advsimdlist_size(const insn_t &ins);

#endif // _ARM_HPP
