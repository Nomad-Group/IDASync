/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"

static const char *const phrases[] =
{
  "F", "LT", "LE", "ULE", "OV",  "MI", "Z",  "C",
  "T", "GE", "GT", "UGT", "NOV", "PL", "NZ", "NC"
};

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_PROC_ASM_AND_BYTESEX);
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  char buf[MAXSTR];

  MakeNull();

  tag_addstr(buf, buf+sizeof(buf), COLOR_ASMDIR, ash.end);
  MakeLine(buf, inf.indent);

  gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);

  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));

  gen_cmt_line(COLSTR("segment %s", SCOLOR_AUTOCMT), sname);

  ea_t org = ea - get_segm_base(Sarea);
  if ( org != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), org);
    gen_cmt_line("%s %s", ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t ea)
{
  char sname[MAXNAMELEN];
  get_segm_name(getseg(ea-1), sname, sizeof(sname));
  gen_cmt_line("end of '%s'", sname);
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf));
  OutMnem();

  out_one_operand(0);

  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  uval_t v;

  switch ( x.type )
  {
    case o_imm:
      out_symbol('#');
      OutValue(x, OOFW_IMM);
      break;

    case o_ind_reg:
      out_symbol('@');

    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
//ig: лучше out_keyword, чем простой OutLine()
//    так цвет будет правильный
      out_keyword(phrases[x.phrase]);
      break;

    case o_displ:
      OutValue(x, OOF_ADDR | OOFW_IMM);  // x.addr
      out_symbol('(');
      OutReg(x.reg);
      out_symbol(')');
      break;

    case o_ind_mem:
      out_symbol('@');

    case o_mem:
    case o_near:
      v = map_addr(x.addr, x.n, x.type != o_near);
      if ( !out_name_expr(x, v, x.addr) )
      {
        const char *name = z8_find_ioport(v);
        if ( name != NULL )
        {
          out_line(name, COLOR_IMPNAME);
        }
        else
        {
          OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
          QueueSet(Q_noName, cmd.ea);
        }
      }
      break;

    case o_void:
      return 0;

    default:
      warning("out: %a: bad optype %d", cmd.ea, x.type);
  }

  return 1;
}

//--------------------------------------------------------------------------
static void out_equ(const char *name, const char *equ, uchar off)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);

  char *p = tag_addstr(buf, end, COLOR_DNAME, name);
  APPCHAR(p, end, ' ');
  p = tag_addstr(p, end, COLOR_KEYWORD, equ);
  APPCHAR(p, end, ' ');
  p = tag_on(p, end, COLOR_NUMBER);
  p += btoa(p, end-p, off);
  tag_off(p, end, COLOR_NUMBER);
  MakeLine(buf, 0);
}

//--------------------------------------------------------------------------
void idaapi z8_data(ea_t ea)
{
  segment_t *s = getseg(ea);
  if ( s != NULL && s->type == SEG_IMEM )
  {
    qstring name;
    if ( get_visible_name(&name, ea) > 0 )
      out_equ(name.begin(), ash.a_equ, uint16(ea - get_segm_base(s)));
  }
  else
  {
    intel_data(ea);
  }
}

//--------------------------------------------------------------------------
void idaapi z8_assumes(ea_t ea)
{
  segment_t *seg = getseg(ea);
  if ( !inf.s_assume || seg == NULL )
    return;
  // always show at the start of code segments
  bool seg_started = (ea == seg->startEA) && (seg->type == SEG_CODE);

  segreg_area_t sra;
  if ( !get_srarea2(&sra, ea, rRp) )
    return;
  bool show = sra.startEA == ea;
  if ( show )
  {
    segreg_area_t prev_sra;
    if ( get_prev_srarea(&prev_sra, ea, rRp) )
      show = sra.val != prev_sra.val;
  }
  if ( seg_started || show )
  {
    sel_t rp = sra.val;
    if ( rp == BADSEL )
      rp = 0;
    char num[MAX_NUMBUF];
    btoa(num, sizeof(num), rp);
    char nbuf[MAXSTR];
    qsnprintf(nbuf, sizeof(nbuf), COLSTR(".rp %s", SCOLOR_ASMDIR), num);
    MakeLine(nbuf, inf.indent);
  }
}
