
#include <ctype.h>
#include "kr1878.hpp"
#include <srarea.hpp>


//----------------------------------------------------------------------
static bool out_port_address(ea_t addr)
{
  const char *name = find_port(addr);
  if ( name != NULL )
  {
    out_line(name, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  if ( !out_port_address(addr) )
  {
    out_tagon(COLOR_ERROR);
    OutLong(addr, 16);
    out_tagoff(COLOR_ERROR);
    QueueSet(Q_noName, cmd.ea);
  }
}


//----------------------------------------------------------------------
static void out_address(ea_t ea, op_t &x)
{
  segment_t *s = getseg(ea);
  ea_t value = s != NULL ? ea - get_segm_base(s) : ea;
  if ( !out_name_expr(x, ea, value) )
  {
    out_tagon(COLOR_ERROR);
    out_snprintf("%a", ea);
    out_tagoff(COLOR_ERROR);
    QueueSet(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
inline void out_ip_rel(int displ)
{
  out_snprintf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
               ash.a_curip, displ);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;
  if ( x.type == o_imm )
    out_symbol('#');
  char buf[MAXSTR];

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);

      break;

    case o_mem:
      // no break;
    case o_near:
      {
        ea = calc_mem(x);
        if ( ea == cmd.ea+cmd.size )
          out_ip_rel(cmd.size);
        else if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      {
       qsnprintf(buf, sizeof(buf), "%%%c%" FMT_EA "x", 'a' + x.reg, x.value);

       ea = calc_data_mem(x, as + x.reg);
       if ( ( ea != BADADDR ) && ( ( x.reg != SR3 ) || ( x.value < 6 ) ) )
       {
           out_line(buf, COLOR_AUTOCMT);
           out_symbol(' ');
           out_address(ea, x);
        }
       else
           out_line(buf, COLOR_REG);

      }
      break;

    default:
      interr("out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  // output instruction mnemonics
  char postfix[4];
  postfix[0] = '\0';

  OutMnem(8, postfix);

  bool comma = out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    if ( comma ) out_symbol(',');
    out_one_operand(1);
  }
  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    out_one_operand(2);
  }


  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 3) ) OutImmChar(cmd.Op3);

  term_output_buffer();

  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
static void print_segment_register(int reg, sel_t value)
{
  if ( reg == ph.regDataSreg ) return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    gen_cmt_line("assume %s = %s", ph.regNames[reg], buf);
  }
  else
  {
    gen_cmt_line("drop %s", ph.regNames[reg]);
  }
}

//--------------------------------------------------------------------------
// function to produce assume directives
void idaapi assumes(ea_t ea)
{
  segment_t *seg = getseg(ea);
  if ( seg == NULL || !inf.s_assume )
    return;
  bool seg_started = (ea == seg->startEA);

  for ( int i = ph.regFirstSreg; i <= ph.regLastSreg; ++i )
  {
    if ( i == ph.regCodeSreg )
      continue;
    segreg_area_t sra;
    if ( !get_srarea2(&sra, ea, i) )
      continue;
    sel_t now  = get_segreg(ea, i);
    if ( seg_started || sra.startEA == ea )
    {
      segreg_area_t prev_sra;
      bool prev_exists = get_srarea2(&prev_sra, ea - 1, i);
      if ( seg_started || (prev_exists && get_segreg(prev_sra.startEA, i) != now) )
        print_segment_register(i, now);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sclas[MAXNAMELEN];
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( strcmp(sclas,"CODE") == 0 )
    printf_line(inf.indent, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( strcmp(sclas,"DATA") == 0 )
    printf_line(inf.indent, COLSTR(".data", SCOLOR_ASMDIR));

  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL);
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  qstring nbuf = get_colored_name(inf.beginEA);
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == NULL )
    printf_line(inf.indent,COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR)
                  " "
                  COLSTR("%s %s",SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

//--------------------------------------------------------------------------
void idaapi kr1878_data(ea_t ea)
{
  intel_data(ea);
}
