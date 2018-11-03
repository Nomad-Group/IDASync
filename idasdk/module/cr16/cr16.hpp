/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _CR16_HPP
#define _CR16_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#define near
#define far
#include "ins.hpp"

// ============================================================
// specflags1 bits
//-----------------------------------------------
#define URR_PAIR        (0x01)  // indirect reference via reg pair

//------------------------------------------------------------------------
// processor registers
enum CR16_registers
{
 rNULLReg,
 rR0, rR1, rR2, rR3, rR4, rR5, rR6, rR7,
 rR8, rR9, rR10, rR11, rR12, rR13, rRA, rSP,
 // special registers
 rPC, rISP, rINTBASE, rPSR, rCFG, rDSR, rDCR,
 rCARL, rCARH, rINTBASEL, rINTBASEH,
 rVcs, rVds
};

//------------------------------------------------------------------------
extern qstring deviceparams;
extern qstring device;

//------------------------------------------------------------------------
void    idaapi CR16_header(outctx_t &ctx);
void    idaapi CR16_footer(outctx_t &ctx);

void    idaapi CR16_segstart(outctx_t &ctx, segment_t *seg);

int     idaapi CR16_ana(insn_t *_insn);
int     idaapi CR16_emu(const insn_t &insn);

#endif
