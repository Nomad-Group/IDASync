/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PDP_HPP
#define _PDP_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include "pdp_ml.h"
//-V::536 octal

extern pdp_ml_t ml;

#define UAS_SECT        0x0001          // Segments are named .SECTION

extern int pflag;

//----------------------------------------------------------------------
// Redefine temporary names
//
#define         bytecmd    auxpref_u8[0]

#define         segval     specval_shorts.low
#define         addr16     addr_shorts.low
#define         ill_imm    specflag1

#define         o_fpreg    o_idpspec0
#define         o_number   o_idpspec1
//------------------------------------------------------------------------
enum pdp_registers
{
  rR0, rR1, rR2, rR3, rR4, rR5, rSP, rPC,
  rAC0, rAC1, rAC2, rAC3, rAC4, rAC5,
  rVcs, rVds
};

//------------------------------------------------------------------------
void    idaapi pdp_header(outctx_t &ctx);
void    idaapi pdp_footer(outctx_t &ctx);

void    idaapi pdp_segstart(outctx_t &ctx, segment_t *seg);

int     idaapi ana(insn_t *_insn);
int     idaapi emu(const insn_t &insn);

void    idaapi pdp_data(outctx_t &ctx, bool analyze_only);

extern netnode ovrtrans;

#endif

