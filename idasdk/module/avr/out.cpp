/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"

//----------------------------------------------------------------------
class out_avr_t : public outctx_t
{
  out_avr_t(void) : outctx_t(BADADDR) {} // not used
public:
  void out_phrase(int phn);
  void out_bad_address(ea_t addr);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_avr_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_avr_t)

//----------------------------------------------------------------------
void out_avr_t::out_phrase(int phn)
{
  switch ( phn )
  {
    case PH_XPLUS:     // X+
      out_register("X");
      out_symbol('+');
      break;
    case PH_MINUSX:    // -X
      out_symbol('-');
    case PH_X:         // X
      out_register("X");
      break;
    case PH_YPLUS:     // Y+
      out_register("Y");
      out_symbol('+');
      break;
    case PH_MINUSY:    // -Y
      out_symbol('-');
    case PH_Y:         // Y
      out_register("Y");
      break;
    case PH_ZPLUS:     // Z+
      out_register("Z");
      out_symbol('+');
      break;
    case PH_MINUSZ:    // -Z
      out_symbol('-');
    case PH_Z:         // Z
      out_register("Z");
      break;
    default:
      error("%a: bad phrase number", insn.ea);
  }
}

//----------------------------------------------------------------------
void out_avr_t::out_bad_address(ea_t addr)
{
  out_tagon(COLOR_ERROR);
  out_btoa(addr, 16);
  out_tagoff(COLOR_ERROR);
  remember_problem(PR_NONAME, insn.ea);
}

//----------------------------------------------------------------------
bool out_avr_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      if ( ram != BADADDR )
      {
        qstring name;
        if ( get_visible_name(&name, ram+x.reg) > 0 )
        {
          out_register(name.begin());
          break;
        }
      }
      out_register(ph.reg_names[x.reg]);
      break;

    case o_imm:
      {
        if ( insn.itype == AVR_cbi
          || insn.itype == AVR_sbic
          || insn.itype == AVR_sbi
          || insn.itype == AVR_sbis )
        {
          const char *bit = find_bit(insn.Op1.addr, (size_t)x.value);
          if ( bit != NULL && bit[0] != '\0' )
          {
            out_line(bit, COLOR_REG);
            break;
          }
        }
        if ( x.specflag1 && is_off1(F) && !is_invsign(insn.ea, F, 1) )
          out_symbol('-');
        int flags = OOFS_IFSIGN|OOFW_8;
        if ( insn.itype == AVR_subi || insn.itype == AVR_sbci )
          flags |= OOF_SIGNED;
        out_value(x, flags);
      }
      break;

    case o_near:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      out_phrase(x.phrase);
      break;

    case o_displ:
      out_phrase(x.phrase);
      out_value(x, OOF_ADDR|OOFS_NEEDSIGN|OOFW_IMM);
      break;

    case o_port:
      {
        const ioport_t *port = find_port(x.addr);
        if ( port != NULL && !port->name.empty() )
          out_register(port->name.c_str());
        else
          out_bad_address(x.addr);
      }
      break;

    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_avr_t::out_insn(void)
{
  // output .org for enties without any labels
  if ( !has_any_name(F) && helper.altval_ea(insn.ea) )
  {
    char buf[MAXSTR];
    btoa(buf, sizeof(buf), insn.ip);
    int saved_flags = forbid_annotations();
    gen_printf(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    restore_ctxflags(saved_flags);
  }

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
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi avr_segstart(outctx_t &ctx, segment_t *Sarea)
{
  if ( is_spec_segm(Sarea->type) )
    return;
  qstring sname;
  qstring sclas;
  get_visible_segm_name(&sname, Sarea);
  get_segm_class(&sclas, Sarea);
  ctx.gen_printf(0,
                 COLSTR("%s", SCOLOR_ASMDIR) " " COLSTR("%s %s", SCOLOR_AUTOCMT),
                 sclas == "CODE"
               ? ".CSEG"
               : sclas == "DATA"
               ? ".DSEG"
               : ".ESEG",
                 ash.cmnt,
                 sname.c_str());
  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    ctx.gen_printf(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi avr_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi avr_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, NULL, device.c_str());
}

//--------------------------------------------------------------------------
void idaapi avr_footer(outctx_t &ctx)
{
  qstring name = get_visible_name(inf.start_ea);
  ctx.gen_printf(inf.indent,
                 COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                 ash.end, ash.cmnt, name.c_str());
}
