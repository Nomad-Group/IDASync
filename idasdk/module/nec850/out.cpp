/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Output
 *
 */
#include "necv850.hpp"
#include "ins.hpp"

//--------------------------------------------------------------------------
// LIST12 table mapping to corresponding registers
static const int list12_table[] =
{
  rR31, // 0
  rR29, // 1
  rR28, // 2
  rR23, // 3
  rR22, // 4
  rR21, // 5
  rR20, // 6
  rR27, // 7
  rR26, // 8
  rR25, // 9
  rR24, // 10
  rEP   // 11
};

// Using the indexes in this table as indexes in list12_table[]
// we can test for bits in List12 in order
static const int list12order_table[] =
{
  6,    // 0  r20
  5,    // 1  r21
  4,    // 2  r22
  3,    // 3  r23
  10,   // 4  r24
  9,    // 5  r25
  8,    // 6  r26
  7,    // 7  r27
  2,    // 8  r28
  1,    // 9  r29
  11,   // 10 r30
  0,    // 11 r31
};

//----------------------------------------------------------------------
class out_nec850_t : public outctx_t
{
  out_nec850_t(void) : outctx_t(BADADDR) {} // not used
public:
  void OutReg(const op_t &r);
  void out_reg_list(uint32 L);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_nec850_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_nec850_t)

//--------------------------------------------------------------------------
bool reg_in_list12(uint16 reg, uint32 L)
{
  if ( rR20 <= reg && reg <= rR31 )
  {
    uint32 idx = list12order_table[reg - rR20];
    return (L & (1 << idx)) != 0;
  }
  return false;
}

//--------------------------------------------------------------------------
void out_nec850_t::out_reg_list(uint32 L)
{
  int last = qnumber(list12_table);
  int in_order = 0, c = 0;
  const char *last_rn = NULL;

  out_symbol('{');
  for ( int i=0; i < qnumber(list12order_table); i++ )
  {
    uint32 idx = list12order_table[i];
    if ( (L & (1 << idx)) == 0 )
      continue;
    c++;
    const char *rn = RegNames[list12_table[idx]];
    if ( last + 1 == i )
      in_order++;
    else
    {
      if ( in_order > 1 )
      {
        out_symbol('-');
        out_register(last_rn);
        out_line(", ", COLOR_SYMBOL);
      }
      else if ( c > 1 )
      {
        out_line(", ", COLOR_SYMBOL);
      }
      out_register(rn);
      in_order = 1;
    }
    last_rn = rn;
    last    = i;
  }
  if ( in_order > 1 )
  {
    out_symbol('-');
    out_register(last_rn);
  }
  out_symbol('}');
}

//--------------------------------------------------------------------------
void idaapi nec850_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
}

//--------------------------------------------------------------------------
void idaapi nec850_footer(outctx_t &ctx)
{
  ctx.gen_empty_line();
  ctx.out_line(ash.end, COLOR_ASMDIR);
  ctx.flush_outbuf(inf.indent);
  ctx.gen_cmt_line( "-------------- end of module --------------");
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, s) could be made const
void idaapi nec850_segstart(outctx_t &ctx, segment_t *s)
{
  qstring sname;
  qstring sclass;

  get_visible_segm_name(&sname, s);
  get_segm_class(&sclass, s);

  const char *p_class;
  if ( (s->perm == (SEGPERM_READ|SEGPERM_WRITE)) && s->type == SEG_BSS )
    p_class = "bss";
  else if ( s->perm == SEGPERM_READ )
    p_class = "const";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_WRITE) )
    p_class = "data";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_EXEC) )
    p_class = "text";
  else if ( s->type == SEG_XTRN )
    p_class = "symtab";
  else
    p_class = sclass.c_str();

  ctx.gen_printf(0, COLSTR(".section \"%s\", %s", SCOLOR_ASMDIR), sname.c_str(), p_class);
}

//--------------------------------------------------------------------------
void idaapi nec850_segend(outctx_t &, segment_t *)
{
}

//----------------------------------------------------------------------
void out_nec850_t::OutReg(const op_t &r)
{
  bool brackets = r.specflag1 & N850F_USEBRACKETS;
  if ( brackets )
    out_symbol('[');
  out_register(ph.reg_names[r.reg]);
  if ( brackets )
    out_symbol(']');
}

//----------------------------------------------------------------------
void out_nec850_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);

  for ( int i=1; i < 3; i++ )
  {
    if ( insn.ops[i].type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(i);
    }
  }
  flush_outbuf();
}

//----------------------------------------------------------------------
// Generate text representation of an instructon operand.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
// The output text is placed in the output buffer initialized with init_output_buffer()
// This function uses out_...() functions from ua.hpp to generate the operand text
// Returns: 1-ok, 0-operand is hidden.
bool out_nec850_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
  case o_void:
    return false;
  case o_reglist:
    out_reg_list(x.value);
    break;
  case o_reg:
    OutReg(x);
    break;
  case o_imm:
    out_value(x, OOFW_IMM | ((x.specflag1 & N850F_OUTSIGNED) ? OOF_SIGNED : 0));
    break;
  case o_near:
  case o_mem:
    if ( !out_name_expr(x, x.addr, BADADDR) )
    {
      out_tagon(COLOR_ERROR);
      out_value(x, OOF_ADDR | OOFW_IMM | OOFW_32);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
    break;
  case o_displ:
    if ( x.addr != 0 || x.reg == rSP )
      out_value(x,
               OOF_ADDR
             | OOFW_16
             | ((x.specflag1 & N850F_OUTSIGNED) ? OOF_SIGNED : 0));  // x.addr
    OutReg(x);
    if ( x.reg != rGP && x.reg != rSP && x.addr == 0 )
    { // add name comment
      xrefblk_t xb;
      for ( bool ok=xb.first_from(insn.ea, XREF_DATA); ok; ok=xb.next_from() )
      {
        if ( has_cmt(F) )
          continue;
        if ( xb.type != dr_R && xb.type != dr_W )
          continue;

        qstring qbuf;
        if ( get_name_expr(&qbuf, insn.ea, x.n, xb.to, BADADDR) > 0 )
          set_cmt(insn.ea, qbuf.begin(), false);
      }
    }
    break;
  default:
    return false;
  }
  return true;
}
