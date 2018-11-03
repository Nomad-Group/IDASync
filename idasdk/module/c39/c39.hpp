/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _C39_HPP
#define _C39_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#define near
#define far
#include "ins.hpp"

// ============================================================
// варианты битновых полей для specflags1 (specflag2 - не исп.)
//-----------------------------------------------
// дополнительные биты к типу ячейки
#define URR_IND         (0x01)  // косвенно, через регистр

//------------------------------------------------------------------------
// список регистров процессора
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum C39_registers ENUM8BIT
{
  rNULLReg,
  rA,
  rX, rY,
  rVcs, rVds
};

extern qstring deviceparams;
extern qstring device;

//------------------------------------------------------------------------
void    idaapi C39_header(outctx_t &ctx);
void    idaapi C39_footer(outctx_t &ctx);
void    idaapi C39_segstart(outctx_t &ctx, segment_t *seg);
int     idaapi C39_ana(insn_t *insn);
int     idaapi C39_emu(const insn_t &insn);
void    idaapi C39_data(outctx_t &ctx, bool analyze_only);

#endif
