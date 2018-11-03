/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef _TMS_HPP
#define _TMS_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:
#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1
#define o_cond          o_idpspec2

#define sib     specflag1
#define Cond    reg

extern int nprc;        // processor number
#define PT_TMS320C5     0
#define PT_TMS320C2     1

inline bool isC2(void) { return nprc == PT_TMS320C2; }


//------------------------------------------------------------------------
enum TMS_registers { rAcc,rP,rBMAR,rAr0,rAr1,rAr2,rAr3,rAr4,rAr5,rAr6,rAr7,rVcs,rVds,rDP };

enum TMS_bits { bit_intm,bit_ovm,bit_cnf,bit_sxm,bit_hm,bit_tc,bit_xf,bit_c };

//------------------------------------------------------------------------
struct predefined_t
{
  uchar addr;
  const char *name;
  const char *cmt;
};

bool is_mpy(const insn_t &insn);
ea_t prevInstruction(ea_t ea);
int  find_ar(const insn_t &insn, ea_t *res);
//------------------------------------------------------------------------
void idaapi header(outctx_t &ctx);
void idaapi footer(outctx_t &ctx);

void idaapi segstart(outctx_t &ctx, segment_t *seg);

int  idaapi ana(insn_t *insn);
int  idaapi emu(const insn_t &insn);
void idaapi tms_assumes(outctx_t &ctx);

#endif
