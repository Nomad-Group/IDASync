/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _PAN_HPP
#define _PAN_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"

//-----------------------------------------------
// Вспомогательные биты
#define URB_ADDR        0x1     // Непоср. аргумент - адрес

//------------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
// список регистров процессора
enum mn102_registers ENUM8BIT
{
  rNULLReg,
  rD0, rD1, rD2, rD3,
  rA0, rA1, rA2, rA3,
  rMDR,rPSW, rPC,
  rVcs, rVds
};

extern qstring deviceparams;
extern qstring device;

//------------------------------------------------------------------------
void    idaapi mn102_header(outctx_t &ctx);
void    idaapi mn102_footer(outctx_t &ctx);

void    idaapi mn102_segstart(outctx_t &ctx, segment_t *seg);

int     idaapi mn102_ana(insn_t *_insn);
int     idaapi mn102_emu(const insn_t &insn);

void    idaapi mn102_data(outctx_t &ctx, bool analyze_only);

#endif
