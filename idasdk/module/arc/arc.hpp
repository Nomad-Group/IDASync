/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2012 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      ARC (Argonaut RISC Core) processor module
 *
 *      Based on code contributed by by Felix Domke <tmbinc@gmx.net>
 */

#ifndef _ARC_HPP
#define _ARC_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <typeinf.hpp>

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

enum processor_subtype_t
{
  prc_arc = 0,                  // ARCTangent-A4 (old 32-bit ISA)
  prc_arcompact = 1,            // ARCtangent-A5 and later (32/16-bit mixed)
};

extern processor_subtype_t ptype;

inline bool is_a4() { return ptype == prc_arc; }

extern netnode helper;      // altval(-1): idp flags
#define CALLEE_TAG   'A'    // altval(ea): callee address for indirect calls
#define DXREF_TAG    'd'    // altval(ea): resolved address for complex calculation (e.g. ADD R1, PC)
#define DSLOT_TAG    's'    // altval(ea): 1: delay slot of an unconditional jump/branch
                            //             2: delay slot of a conditional jump/branch
                            //             3: delay slot of a jl/bl

inline void set_callee(ea_t ea, ea_t callee) { helper.easet(ea, callee, CALLEE_TAG); }
inline ea_t get_callee(ea_t ea) { return helper.eaget(ea, CALLEE_TAG); }
inline void del_callee(ea_t ea) { helper.eadel(ea, CALLEE_TAG); }

inline void set_dxref(ea_t ea, ea_t dxref) { helper.easet(ea, dxref, DXREF_TAG); }
inline ea_t get_dxref(ea_t ea) { return helper.eaget(ea, DXREF_TAG); }
inline void del_dxref(ea_t ea) { helper.eadel(ea, DXREF_TAG); }

extern ushort idpflags;

#define ARC_SIMPLIFY    0x01
#define ARC_INLINECONST 0x02
#define ARC_TRACKREGS   0x04

//------------------------------------------------------------------
enum RegNo
{
  R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
  R8,   R9,   R10,  R11,  R12,  R13,  R14,  R15,
  R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
  R24,  R25,  R26,  R27,  R28,  R29,  R30,  R31,

  R32,  R33,  R34,  R35,  R36,  R37,  R38,  R39,
  R40,  R41,  R42,  R43,  R44,  R45,  R46,  R47,
  R48,  R49,  R50,  R51,  R52,  R53,  R54,  R55,
  R56,  R57,  R58,  R59,  R60,  R61,  R62,  R63,

  CF, ZF, NF, VF,

  rVcs, rVds,      // virtual registers for code and data segments

  // aliases

  GP = R26,        // Global Pointer
  FP = R27,        // Frame Pointer
  SP = R28,        // Stack Pointer
  ILINK1 = R29,    // Level 1 interrupt link register
  ILINK2 = R30,    // Level 2 interrupt link register
  BLINK  = R31,    // Branch link register
  LP_COUNT = R60,  // Loop count register
  PCL = R63,       // 32-bit aligned PC value (ARCompact)

  // optional extension
  MLO  = R57,      // Multiply low 32 bits, read only
  MMID = R58,      // Multiply middle 32 bits, read only
  MHI  = R59,      // Multiply high 32 bits, read only
};

#define SHIMM_F 61 // Short immediate data indicator setting flags
#define LIMM    62 // Long immediate data indicator
#define SHIMM   63 // Short immediate data indicator not setting flags (NB: not used in ARCompact)

//---------------------------------
inline bool is_imm(int regno)
{
  if ( regno == SHIMM_F || regno == LIMM )
    return true;
  if ( regno == SHIMM )
    return is_a4();
  return false;
}

inline int getreg(const op_t &x)
{
  return x.type == o_reg ? x.reg : -1;
}

inline bool isreg(const op_t &x, int reg)
{
  return getreg(x) == reg;
}

inline bool issp(const op_t &x) { return isreg(x, SP); }

//---------------------------------
// cmd.auxpref bits
// instructions that use condition flags (Bcc, Jcc)
#define aux_f           0x0100  // Flags set field (.f postfix)
#define aux_nmask       0x0060  // Jump/Call nullify instruction mode
#define    aux_nd         0x00  // No Delayed instruction slot (only execute next instruction when not jumping)
#define    aux_d          0x20  // Delayed instruction slot (always execute next instruction)
#define    aux_jd         0x40  // Jump Delayed instruction slot (only execute next instruction when jumping)
#define aux_cmask       0x001F  // condition code mask
// load/store instructions flags (Di.AA.ZZ.X)
#define aux_di          0x0020  // direct to memory (cache bypass) (.di suffix)
#define aux_amask       0x0018  // Address write-back
#define     aux_anone     0x00  // no writeback
#define     aux_a         0x08  // pre-increment (.a or .aw)
#define     aux_ab        0x10  // post-increment (.ab)
#define     aux_as        0x18  // scaled access (.as)
#define aux_zmask       0x0006  // size mask
#define     aux_l          0x0  // long size (no suffix)
#define     aux_w          0x4  // word size (.w suffix)
#define     aux_b          0x2  // byte size (.b suffix)
#define aux_x           0x0001  // Sign extend field (.x suffix)

#define aux_pcload      0x0200  // converted pc-relative to memory load (used when ARC_INLINECONST is set)

#define cond(ins)  ((ins).itype <= ARC_store_instructions ? cAL : ((ins).auxpref & aux_cmask))

// Operand types:

// o_phrase
#define secreg          specflag1       // o_phrase: the second register is here: [op.phrase, op.secreg]

// o_displ
#define membase         specflag1       // o_displ: if set, displacement is the base value: [op.addr, op.reg]
                                        // this is important for scaled loads, e.g. ld.as r1, [0x23445, r2]

//------------------------------------------------------------------
// Condition codes:
enum cond_t
{
  cAL=0, cRA=0,        // Always                                                      1 0x00
  cEQ=1, cZ=1,         // Zero                                                        Z 0x01
  cNE=2, cNZ=2,        // Non-Zero                                                   /Z 0x02
  cPL=3, cP=3,         // Positive                                                   /N 0x03
  cMI=4, cN=4,         // Negative                                                    N 0x04
  cCS=5, cC=5,  cLO=5, // Carry set, lower than (unsigned)                            C 0x05
  cCC=6, cNC=6, cHS=6, // Carry clear, higher or same (unsigned)                     /C 0x06
  cVS=7, cV=7,         // Over-flow set                                               V 0x07
  cVC=8, cNV=8,        // Over-flow clear                                            /V 0x08
  cGT=9,               // Greater than (signed)  (N and V and /Z) or (/N and /V and /Z) 0x09
  cGE=0x0A,            // Greater than or equal to (signed)    (N and V) or (/N and /V) 0x0A
  cLT=0x0B,            // Less than (signed)                   (N and /V) or (/N and V) 0x0B
  cLE=0x0C,            // Less than or equal to (signed)  Z or (N and /V) or (/N and V) 0x0C
  cHI=0x0D,            // Higher than (unsigned)                              /C and /Z 0x0D
  cLS=0x0E,            // Lower than or same (unsigned)                          C or Z 0x0E
  cPNZ=0x0F,           // Positive non-zero                                   /N and /Z 0x0F
};

// ARC ABI conventions from gdb/arc-tdep.h
#define ARC_ABI_GLOBAL_POINTER                 26
#define ARC_ABI_FRAME_POINTER                  27
#define ARC_ABI_STACK_POINTER                  28

#define ARC_ABI_FIRST_CALLEE_SAVED_REGISTER    13
#define ARC_ABI_LAST_CALLEE_SAVED_REGISTER     26

#define ARC_ABI_FIRST_ARGUMENT_REGISTER         0
#define ARC_ABI_LAST_ARGUMENT_REGISTER          7

#define ARC_ABI_RETURN_REGNUM                   0
#define ARC_ABI_RETURN_LOW_REGNUM               0
#define ARC_ABI_RETURN_HIGH_REGNUM              1

//------------------------------------------------------------------------
// does 'ins' have a delay slot? (next instruction is executed before branch/jump)
#define has_dslot(ins) (ins.itype <= ARC_store_instructions ? false : (ins.auxpref & aux_nmask) != 0)
// is 'ea' in a delay slot of a branch/jump?
inline bool is_dslot(ea_t ea, bool including_calls = true)
{
  nodeidx_t v = helper.altval_ea(ea, DSLOT_TAG);
  if ( including_calls )
    return v != 0;
  else
    return v == 1 || v == 2;
}

//------------------------------------------------------------------------
void idaapi arc_header(outctx_t &ctx);
void idaapi arc_footer(outctx_t &ctx);

void idaapi arc_segstart(outctx_t &ctx, segment_t *seg);

int idaapi ana(insn_t *out);
int idaapi emu(const insn_t &insn);
int idaapi is_align_insn(ea_t ea);

int idaapi is_sp_based(const insn_t &insn, const op_t & x);
bool idaapi create_func_frame(func_t * pfn);
int idaapi arc_get_frame_retsize(const func_t * pfn);
bool copy_insn_optype(const insn_t &insn, const op_t &x, ea_t ea, void *value = NULL, bool force = false);
bool is_arc_call_insn(const insn_t &insn);
bool is_arc_return_insn(const insn_t &insn);
bool is_arc_basic_block_end(const insn_t &insn);
void del_insn_info(ea_t ea);

int get_arc_fastcall_regs(const int **regs);
bool calc_arc_arglocs(func_type_data_t *fti);
bool calc_arc_varglocs(
        func_type_data_t *fti,
        regobjs_t *regargs,
        int nfixed);
bool calc_arc_retloc(argloc_t *retloc, const tinfo_t &tif, cm_t cc);
int use_arc_regarg_type(ea_t ea, const funcargvec_t &rargs);
void use_arc_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);

#endif
