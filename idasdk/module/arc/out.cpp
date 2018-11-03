/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"

// generic condition codes
static const char *const ccode[] =
{
  "",   "z",  "nz", "p",
  "n",  "c",  "nc", "v",
  "nv", "gt", "ge", "lt",
  "le", "hi", "ls", "pnz",
  "ss", "sc", "c0x12", "c0x13",
  "c0x14", "c0x15", "c0x16", "c0x17",
  "c0x18", "c0x19", "c0x1A", "c0x1B",
  "c0x1C", "c0x1D", "c0x1E", "c0x1F",
};

// condition codes for branches
static const char *const ccode_b[] =
{
  "",   "eq", "ne", "pl",
  "mi", "lo", "hs", "vs",
  "vc", "gt", "ge", "lt",
  "le", "hi", "ls", "pnz",
  "ss", "sc", "c0x12", "c0x13",
  "c0x14", "c0x15", "c0x16", "c0x17",
  "c0x18", "c0x19", "c0x1A", "c0x1B",
  "c0x1C", "c0x1D", "c0x1E", "c0x1F",
};

/* jump delay slot codes */
static const char ncode[][4] = { "", ".d", ".jd", ".d?" };

//----------------------------------------------------------------------
class out_arc_t : public outctx_t
{
  out_arc_t(void) : outctx_t(BADADDR) {} // not used
public:
  void outreg(int rn);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_arc_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_arc_t)

//----------------------------------------------------------------------
void out_arc_t::outreg(int rn)
{
  const char *regname = (rn < ph.regs_num) ? ph.reg_names[rn] : "<bad register>";
  out_register(regname);
}

//----------------------------------------------------------------------
/* outputs an operand 'x' */
bool out_arc_t::out_operand(const op_t & x)
{
  ea_t v;
  switch ( x.type )
  {
    case o_reg:
      outreg(x.reg);
      break;

    case o_phrase:
      out_symbol('[');
      outreg(x.reg);
      out_symbol(',');
      outreg(x.secreg);
      out_symbol(']');
      break;

    case o_imm:
      out_value(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_mem:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        if ( x.type == o_mem && (insn.auxpref & aux_pcload) != 0 )
        {
          // A little hack to make the output
          // more readable...
          op_t y = {0};
          if ( copy_insn_optype(insn, x, ea, &y.value) )
          {
            y.dtype = x.dtype;
            y.flags = OF_SHOW;
            out_symbol('=');
            ea_t insn_ea_sav = insn_ea;
            flags_t savedF = F;
            insn_ea = ea;    // change context
            F = get_flags(ea);
            out_value(y, OOFS_IFSIGN|OOFW_IMM);
            insn_ea = insn_ea_sav;    // restore context
            F = savedF;
            break;
          }
        }
        out_symbol('[');
        if ( insn.itype != ARC_lr && insn.itype != ARC_sr )
        {
          if ( !out_name_expr(x, ea, x.addr) )
          {
            out_tagon(COLOR_ERROR);
            out_btoa(uint32(x.addr), 16);
            out_tagoff(COLOR_ERROR);
            remember_problem(PR_NONAME, insn.ea);
          }
        }
        else
        {
          out_btoa(uint32(x.addr), 16);
        }
        out_symbol(']');
      }
      break;

    case o_near:
      v = to_ea(insn.cs, x.addr);
      if ( !out_name_expr(x, v, x.addr) )
      {
        out_value(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
        break;
      }
      break;

    case o_displ:
      // membase=0: [reg, #addr]
      // membase=1: [#addr, reg]
      out_symbol('[');
      if ( x.membase == 0 )
        outreg(x.reg);
      if ( x.addr != 0
        || is_off(F, x.n)
        || is_stkvar(F, x.n)
        || is_enum(F, x.n)
        || is_stroff(F, x.n) )
      {
        if ( x.membase == 0 )
          out_symbol(',');
        out_value(x, OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|OOFW_32);
        if ( x.membase != 0 )
          out_symbol(',');
      }
      if ( x.membase != 0 )
        outreg(x.reg);
      out_symbol(']');
      break;

    default:
      out_symbol('?');
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
inline bool is_branch(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case ARC_b:
    case ARC_lp:
    case ARC_bl:
    case ARC_j:
    case ARC_jl:
    case ARC_br:
    case ARC_bbit0:
    case ARC_bbit1:
      return true;
  }
#ifndef NDEBUG
  // delay slot bits must be only set for branches
  QASSERT(10184, !has_dslot(insn));
#endif
  return false;
}

//----------------------------------------------------------------------
void out_arc_t::out_proc_mnem(void)
{
  char postfix[MAXSTR];
  postfix[0] = '\0';
  if ( insn.itype == ARC_null )
  {
    uint32 code = get_dword(insn.ea);

    int i = (code>>27)&31;
    if ( i == 3 )
    {
      int c = (code>>9)&63;
      qsnprintf(postfix, sizeof(postfix), "ext%02X_%02X", i, c);
    }
    else
    {
      qsnprintf(postfix, sizeof(postfix), "ext%02X", i);
    }
  }

  /* if we have a load or store instruction, flags are used a bit different */
  if ( insn.itype <= ARC_store_instructions )
  {
    switch ( insn.auxpref & aux_zmask )
    {
      case 0:
        break;
      case aux_b:
        qstrncat(postfix, "b", sizeof(postfix));
        break;
      case aux_w:
        qstrncat(postfix, "w", sizeof(postfix));
        break;
      default:
        qstrncat(postfix, "?", sizeof(postfix));
        break;
    }
    if ( insn.auxpref & aux_x )
      qstrncat(postfix, ".x", sizeof(postfix));
    switch ( insn.auxpref & aux_amask )
    {
      case 0:
        break;
      case aux_a:
        qstrncat(postfix, ".a", sizeof(postfix));
        break;
      case aux_as:
        qstrncat(postfix, ".as", sizeof(postfix));
        break;
      case aux_ab:
        qstrncat(postfix, ".ab", sizeof(postfix));
        break;
      default:
        qstrncat(postfix, "?", sizeof(postfix));
        break;
    }
    if ( insn.auxpref & aux_di )
      qstrncat(postfix, ".di", sizeof(postfix));
  }
  else if ( cond(insn) != cAL )
  {
    if ( is_branch(insn) )
    {
      qstrncat(postfix, ccode_b[cond(insn)], sizeof(postfix));
    }
    else
    {
      qstrncat(postfix, ".", sizeof(postfix));
      qstrncat(postfix, ccode[cond(insn)], sizeof(postfix));
    }
  }
  if ( is_branch(insn) )  // delay slot code
    qstrncat(postfix, ncode[(insn.auxpref >> 5) & 3], sizeof(postfix));
  else if ( (insn.auxpref & aux_f) && (insn.itype != ARC_flag) )   // flag implicitly sets this bit
    qstrncat(postfix, ".f", sizeof(postfix));

  out_mnem(8, postfix);    // output instruction mnemonics
}

//----------------------------------------------------------------------
void out_arc_t::out_insn(void)
{
  out_mnemonic();
  if ( insn.Op1.type != o_void )
    out_one_operand(0);   // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);   // output the second operand
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);   // output the third operand
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();

  // add comments for indirect calls or calculated data xrefs
  nodeidx_t callee = get_callee(insn.ea);
  if ( callee == BADADDR )
    callee = get_dxref(insn.ea);
  if ( callee != BADADDR )
    set_comment_addr(callee & ~1);
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void idaapi arc_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// generate start of a segment
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi arc_segstart(outctx_t &ctx, segment_t *Sarea)
{
  qstring name;
  get_visible_segm_name(&name, Sarea);
  ctx.gen_printf(0, COLSTR(".section %s", SCOLOR_ASMDIR), name.c_str());
  if ( (inf.outflags & OFLG_GEN_ORG) != 0 )
  {
    adiff_t org = ctx.insn_ea - get_segm_base(Sarea);

    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];

      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(0, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly
void idaapi arc_footer(outctx_t &ctx)
{
  ctx.gen_empty_line();

  ctx.out_line(".end", COLOR_ASMDIR);

  qstring name;
  if ( get_colored_name(&name, inf.start_ea) > 0 )
  {
    ctx.out_line(" #");
    ctx.out_line(name.begin());
  }
  ctx.flush_outbuf(inf.indent);
}
