/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _ST20_HPP
#define _ST20_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"

//------------------------------------------------------------------
enum regnum_t
{
  Areg,       // Evaluation stack register A
  Breg,       // Evaluation stack register B
  Creg,       // Evaluation stack register C
  Iptr,       // Instruction pointer register, pointing to the next instruction to be executed
  Status,     // Status register
  Wptr,       // Work space pointer, pointing to the stack of the currently executing process
  Tdesc,      // Task descriptor
  IOreg,      // Input and output register
  cs,
  ds,

};

//------------------------------------------------------------------
extern netnode helper;
extern int procnum;
#define PROC_C1 0
#define PROC_C4 1

inline bool isc4(void) { return procnum == PROC_C4; }

ea_t calc_mem(const insn_t &insn, ea_t ea); // map virtual to physical ea
//------------------------------------------------------------------
void interr(const insn_t &insn, const char *module);

void idaapi st20_header(outctx_t &ctx);
void idaapi st20_footer(outctx_t &ctx);

void idaapi st20_segstart(outctx_t &ctx, segment_t *seg);
void idaapi st20_segend(outctx_t &ctx, segment_t *seg);
void idaapi st20_assumes(outctx_t &ctx);         // function to produce assume directives

int  idaapi st20_ana(insn_t *insn);
int  idaapi st20_emu(const insn_t &insn);

int  idaapi is_align_insn(ea_t ea);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn);           // can a function start here?

#endif // _ST20_HPP
