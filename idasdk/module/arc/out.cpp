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
static const char * const ccode[] =
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
static const char * const ccode_b[] =
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

inline void outreg(int rn)
{
  const char *regname = (rn < ph.regsNum) ? ph.regNames[rn] : "<bad register>";
  out_register(regname);
}

/* outputs an operand 'x' */
bool idaapi outop(op_t & x)
{
// const char *ptr;
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
      OutValue(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_mem:
      {
        ea_t ea = toEA(cmd.cs, x.addr);
        if ( x.type == o_mem && (cmd.auxpref & aux_pcload) != 0 )
        {
          // A little hack to make the output
          // more readable...
          op_t y = {0};
          if ( copy_insn_optype(x, ea, &y.value) )
          {
            ea_t saved_ea = cmd.ea;
            flags_t saved_flags = uFlag;
            y.dtyp  = x.dtyp;
            y.flags = OF_SHOW;
            uFlag = get_flags_novalue(ea);
            cmd.ea = ea;
            out_symbol('=');
            OutValue(y, OOFS_IFSIGN|OOFW_IMM);
            cmd.ea = saved_ea;
            uFlag  = saved_flags;
            break;
          }
        }
        out_symbol('[');
        if ( cmd.itype != ARC_lr && cmd.itype != ARC_sr )
        {
          if ( !out_name_expr(x, ea, x.addr) )
          {
            out_tagon(COLOR_ERROR);
            OutLong(uint32(x.addr), 16);
            out_tagoff(COLOR_ERROR);
            QueueSet(Q_noName, cmd.ea);
          }
        }
        else
        {
            OutLong(uint32(x.addr), 16);
        }
        out_symbol(']');
      }
      break;

    case o_near:
      v = toEA(cmd.cs, x.addr);
      if (!out_name_expr(x, v, x.addr))
      {
        OutValue(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_32);
        QueueSet(Q_noName, cmd.ea);
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
         || isOff(uFlag,x.n)
         || isStkvar(uFlag,x.n)
         || isEnum(uFlag,x.n)
         || isStroff(uFlag,x.n) )
      {
        if ( x.membase == 0 )
          out_symbol(',');
        OutValue(x, OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|OOFW_32);
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

inline bool is_branch()
{
  switch ( cmd.itype )
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
  QASSERT(10184, !has_dslot(cmd));
#endif
  return false;
}

void idaapi out(void)
{
  char buf[MAXSTR];
  char postfix[MAXSTR] = "";

  init_output_buffer(buf, sizeof(buf));

  if ( cmd.itype == ARC_null )
  {
    uint32 code = get_long(cmd.ea);

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
  if ( cmd.itype <= ARC_store_instructions )
  {
    switch ( cmd.auxpref & aux_zmask )
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
    if ( cmd.auxpref & aux_x )
      qstrncat(postfix, ".x", sizeof(postfix));
    switch ( cmd.auxpref & aux_amask )
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
    if ( cmd.auxpref & aux_di )
      qstrncat(postfix, ".di", sizeof(postfix));
  }
  else if ( cmd_cond() != cAL )
  {
    if ( is_branch() )
    {
      qstrncat(postfix, ccode_b[cmd_cond()], sizeof(postfix));
    }
    else
    {
      qstrncat(postfix, ".", sizeof(postfix));
      qstrncat(postfix, ccode[cmd_cond()], sizeof(postfix));
    }
  }
  if ( is_branch() )  // delay slot code
    qstrncat(postfix, ncode[(cmd.auxpref >> 5) & 3], sizeof(postfix));
  else if ( (cmd.auxpref & aux_f) && (cmd.itype != ARC_flag) )   // flag implicitly sets this bit
    qstrncat(postfix, ".f", sizeof(postfix));

  OutMnem(8, postfix);          // output instruction mnemonics

  if (cmd.Op1.type != o_void)
    out_one_operand(0);       // output the first operand

  if (cmd.Op2.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);       // output the second operand
  }

  if (cmd.Op3.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);       // output the third operand
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments

  if (isVoid(cmd.ea, uFlag, 0))
    OutImmChar(cmd.Op1);
  if (isVoid(cmd.ea, uFlag, 1))
    OutImmChar(cmd.Op2);
  if (isVoid(cmd.ea, uFlag, 2))
    OutImmChar(cmd.Op3);

  // add comments for indirect calls or calculated data xrefs
  ea_t callee = helper.altval(cmd.ea)-1;
  if ( callee == BADADDR )
    callee = helper.altval(cmd.ea, DXREF_TAG)-1;
  if ( callee != BADADDR )
  {
    qstring name;
    if ( get_colored_short_name(&name, callee & ~1, GN_INSNLOC) > 0 )
    {
      out_line(" ; ", COLOR_AUTOCMT);
      OutLine(name.begin());
    }
  }
  term_output_buffer();
  gl_comm = 1;                  // ask to attach a possible user defined comment to it
  MakeLine(buf);                // pass the generated line to the kernel
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void idaapi header(void)
{
  gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// generate start of a segment

void idaapi segstart(ea_t ea)
{
  char name[MAXNAMELEN];
  segment_t *Sarea = getseg(ea);

  get_segm_name(Sarea, name, sizeof(name));
  printf_line(0, COLSTR(".section %s", SCOLOR_ASMDIR), name);
  if (inf.s_org)
  {
    adiff_t org = ea - get_segm_base(Sarea);

    if (org != 0)
    {
      char buf[MAX_NUMBUF];

      btoa(buf, sizeof(buf), org);
      printf_line(0, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void idaapi footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);

  MakeNull();
  register char *p = tag_addstr(buf, end, COLOR_ASMDIR, ".end");

  qstring name;
  if ( get_colored_name(&name, inf.beginEA) > 0 )
  {
    APPCHAR(p, end, ' ');
    APPCHAR(p, end, '#');
    APPEND(p, end, name.begin());
  }
  MakeLine(buf, inf.indent);
}
