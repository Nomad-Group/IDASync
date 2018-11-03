/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_6502_t : public outctx_t
{
  out_6502_t(void) : outctx_t(BADADDR) {} // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_6502_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_6502_t)

//----------------------------------------------------------------------
bool out_6502_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      out_register("A");
      break;
    case o_imm:
      out_symbol('#');
      out_value(x, 0);
      break;
    case o_near:
    case o_mem:
      if ( insn.indirect )
        out_symbol('(');
      {
        ea_t v = map_ea(insn, x, x.type == o_near);
        if ( !out_name_expr(x, v, x.addr) )
          out_value(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_16|OOF_ZSTROFF);
      }
      if ( insn.indirect )
        out_symbol(')');
      break;
    case o_displ:
      switch ( x.phrase )
      {
        case rX:
        case rY:
        case zX:
        case zY:
          out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
          out_symbol(',');
          out_register((x.phrase == zX || x.phrase == rX) ? "X" : "Y");
          break;
        case riX:
          out_symbol('(');
          out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
          out_symbol(',');
          out_register("X");
          out_symbol(')');
          break;
        case riY:
          out_symbol('(');
          out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
          out_symbol(')');
          out_symbol(',');
          out_register("Y");
          break;
        default:
          goto err;
      }
      break;
    case o_void:
      return 0;
    default:
err:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_6502_t::out_insn(void)
{
  out_mnemonic();
  out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void idaapi header(outctx_t &ctx)
{
  ctx.gen_cmt_line("%s Processor:        %s", ash.cmnt, inf.procname);
  ctx.gen_cmt_line("%s Target assembler: %s", ash.cmnt, ash.name);
  if ( ash.header != NULL )
    for ( const char *const *ptr = ash.header; *ptr != NULL; ptr++ )
      ctx.flush_buf(*ptr, 0);
}

//--------------------------------------------------------------------------
//lint -e{1764} ctx could be const
//lint -e{818} seg could be const
void idaapi segstart(outctx_t &ctx, segment_t *seg)
{
  ea_t ea = ctx.insn_ea;
  qstring name;
  get_visible_segm_name(&name, seg);
  if ( ash.uflag & UAS_SECT )
  {
    ctx.gen_printf(0, COLSTR("%s: .section", SCOLOR_ASMDIR), name.c_str());
  }
  else
  {
    ctx.gen_printf(inf.indent,
                   COLSTR("%s.segment %s", SCOLOR_ASMDIR),
                   (ash.uflag & UAS_NOSEG) ? ash.cmnt : "",
                   name.c_str());
    if ( ash.uflag & UAS_SELSG )
      ctx.flush_buf(name.c_str(), inf.indent);
    if ( ash.uflag & UAS_CDSEG )
      ctx.flush_buf(COLSTR("CSEG", SCOLOR_ASMDIR), inf.indent); // XSEG - eXternal memory
  }
  if ( (inf.outflags & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ea - get_segm_base(seg);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi footer(outctx_t &ctx)
{
  char buf[MAXSTR];
  if ( ash.end != NULL )
  {
    ctx.gen_empty_line();
    char *ptr = buf;
    char *end = buf + sizeof(buf);
    APPEND(ptr, end, ash.end);
    qstring name;
    if ( get_colored_name(&name, inf.start_ea) > 0 )
    {
      if ( ash.uflag & UAS_NOENS )
        APPEND(ptr, end, ash.cmnt);
      APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, name.begin());
    }
    ctx.flush_buf(buf, inf.indent);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}
