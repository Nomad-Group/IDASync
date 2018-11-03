/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _TOSH_HPP
#define _TOSH_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"

//-----------------------------------------------
// Increment/decrement
#define URB_DECR        (0x80)  // decrement
#define URB_DCMASK      (0x07)  // mask or decrement
#define URB_UDEC        (0x40)  // singleton decrement
#define URB_UINC        (0x20)  // signleto increment

// specflag1 bits
#define URB_WORD        (1)     // second index register is word
#define URB_LDA         (2)     // insn uses address not the content
#define URB_LDA2        (4)     // same, but may constant!

//------------------------------------------------------------------------
enum T900_registers
{
  rNULLReg,
  rW, rA, rB, rC, rD, rE, rH, rL,
  rWA, rBC, rDE, rHL, rIX, rIY, rIZ, rSP,
  rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP,
  rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH,
  rVcs, rVds
};

// phrases
enum T900_phrases
{
  rNULLPh,
  fCF,fCLT,fCLE,fCULE,fCPE,fCMI,fCZ,fCC,
  fCT,fCGE,fCGT,fCUGT,fCPO,fCPL,fCNZ,fCNC,
  fSF,fSF1,
  fSR, fPC
};

//------------------------------------------------------------------------
extern qstring deviceparams;
extern qstring device;

//------------------------------------------------------------------------
void idaapi T900_header(outctx_t &ctx);
void idaapi T900_footer(outctx_t &ctx);

void idaapi T900_segstart(outctx_t &ctx, segment_t *seg);

int  idaapi T900_ana(insn_t *_insn);
int  idaapi T900_emu(const insn_t &insn);

void idaapi T900_data(outctx_t &ctx, bool analyze_only);

#endif
