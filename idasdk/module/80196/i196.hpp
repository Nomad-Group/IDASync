/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#ifndef _I196_HPP
#define _I196_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:

#define o_indirect      o_idpspec0      // [addr]
#define o_indirect_inc  o_idpspec1      // [addr]+
#define o_indexed       o_idpspec2      // addr[value]
#define o_bit           o_idpspec3

extern uint32 intmem;
extern uint32 sfrmem;

extern int extended;

//------------------------------------------------------------------------

enum i196_registers { rVcs, rVds, WSR, WSR1 };

typedef struct
{
  uchar addr;
  const char *name;
  const char *cmt;
} predefined_t;

//------------------------------------------------------------------------
void idaapi i196_header(outctx_t &ctx);
void idaapi i196_footer(outctx_t &ctx);

void idaapi i196_segstart(outctx_t &ctx, segment_t *seg);
void idaapi i196_segend(outctx_t &ctx, segment_t *seg);

int  idaapi ana(insn_t *_insn);
int  idaapi emu(const insn_t &insn);

//void i196_data(ea_t ea);

#endif
