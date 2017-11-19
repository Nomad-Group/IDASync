#include "java.hpp"
#include "oututil.hpp"

static char *g_bufbeg = NULL;
static uint32 g_bufsize;
uint32 maxpos, curpos;
uchar user_limiter;
//nexts only for out
bool no_prim;
size_t outcnt;
static const char *ref_pos;

//--------------------------------------------------------------------------
// returns number of positions advanced
int out_commented(const char *p, color_t color)
{
  if ( color != COLOR_NONE )
    out_tagon(color);
  int npos = out_snprintf("%s %s", ash.cmnt, p);
  if ( color != COLOR_NONE )
    out_tagoff(color);
  return npos;
}


//----------------------------------------------------------------------
bool change_line(bool main)
{
  out_zero();
  bool overflow = false;
  if ( g_bufbeg != NULL )
  {
    outcnt = 0;
    uchar sv = inf.indent;
    inf.indent = (uchar)curpos;
    overflow = MakeLine(g_bufbeg, main ? -1 : curpos);
    inf.indent = sv;
    init_output_buffer(g_bufbeg, g_bufsize);  // for autocomment with call fmtName
  }
  return overflow;
}

//----------------------------------------------------------------------
static size_t putLine(void)
{
  color_t color = COLOR_NONE;

  out_zero();
  if ( g_bufbeg != NULL )
  {
    char *p = strrchr(g_bufbeg, COLOR_ON);
    if ( p != NULL && p[1] && strchr(p+2, COLOR_OFF) == NULL )   // second - PARANOYA
    {
      color = (color_t)*(p + 1);
      out_tagoff(color);
    }
  }
  out_symbol('\\');
  if ( change_line(curpos != 0 && !no_prim) )
    return 0;
  curpos = 0;
  if ( color != COLOR_NONE )
    out_tagon(color);
  ref_pos = get_output_ptr();
  return maxpos;
}

//----------------------------------------------------------------------
bool checkLine(size_t size)
{
  if ( g_bufbeg == NULL )
    return true;
  if ( maxpos - curpos > outcnt + size )
    return true;
  return putLine() != 0;
}

//----------------------------------------------------------------------
bool chkOutLine(const char *str, size_t len)
{
  if ( !checkLine(len) )
    return true;
  outcnt += len;
  OutLine(str);
  return false;
}

//----------------------------------------------------------------------
bool chkOutKeyword(const char *str, uint len)
{
  if ( !checkLine(len) )
    return true;
  OutKeyword(str, len);
  return false;
}

//----------------------------------------------------------------------
bool chkOutSymbol(char c)
{
  if ( !checkLine(1) )
    return true;
  ++outcnt;
  out_symbol(c);
  return false;
}

//----------------------------------------------------------------------
bool chkOutChar(char c)
{
  if ( !checkLine(1) )
    return true;
  ++outcnt;
  OutChar(c);
  return false;
}

//----------------------------------------------------------------------
bool chkOutSymSpace(char c)
{
  if ( !checkLine(2) )
    return true;
  out_symbol(c);
  OutChar(' ');
  outcnt += 2;
  return false;
}

//----------------------------------------------------------------------
uchar putShort(ushort value, uchar wsym)
{
  char *p = get_output_ptr();

  out_tagon(COLOR_ERROR);
  if ( wsym )
    OutChar(wsym);
  OutLong(value,
#ifdef __debug__
                debugmode ? 16 :
#endif
                10);
  out_tagoff(COLOR_ERROR);

  char tmpstr[32];
  char *end = set_output_ptr(p);
  size_t len = end - p;
  qstrncpy(tmpstr, p, qmin(len+1, sizeof(tmpstr)));
  return chkOutLine(tmpstr, tag_strlen(tmpstr));
}

//----------------------------------------------------------------------
char outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad)
{
  char buf[MAXSTR];

  if ( get_name_expr(from, n, ea + off, off, buf, sizeof(buf)) <= 0 )
  {
    if ( loadpass >= 0 )
      QueueSet(Q_noName, cmd.ea);
    return 0;
  }
  if ( chkOutLine(buf, tag_strlen(buf)) )
  {
    *rbad = 1;
    return 0;
  }
  return 1;
}

//---------------------------------------------------------------------------
uchar putVal(const op_t &x, uchar mode, uchar warn)
{
  char *ptr = get_output_ptr();
  {
    flags_t sv_uFlag = uFlag;
    uFlag = 0;
    OutValue(x, mode);
    uFlag = sv_uFlag;
  }

  char str[MAXSTR];
  char *end = set_output_ptr(ptr);
  size_t len = end - ptr;
  qstrncpy(str, ptr, qmin(len+1, sizeof(str)));

  if ( warn )
    out_tagon(COLOR_ERROR);

  if ( warn )
    len = tag_remove(str, str, 0);
  else
    len = tag_strlen(str);

  if ( chkOutLine(str, len) )
    return 0;

  if ( warn )
    out_tagoff(COLOR_ERROR);
  return 1;
}

//----------------------------------------------------------------------
//static _PRMPT_ outProc = putLine;
CASSERT(MIN_ARG_SIZE >= 2 && MIN_ARG_SIZE < 30);

uchar OutUtf8(ushort index, fmt_t mode, color_t color)
{
  size_t size = (maxpos - curpos) - outcnt;

  if ( (int)size <= MIN_ARG_SIZE )
  {
   DEB_ASSERT(((int)size < 0), "OutUtf8");
   size = putLine();
   if ( size == 0 )
     return 1;
  }

  if ( color != COLOR_NONE )
    out_tagon(color);
  ref_pos = get_output_ptr();
  if ( fmtString(index, size, mode, putLine) < 0 )
    return 1;
  outcnt += get_output_ptr() - ref_pos;
  if ( color != COLOR_NONE )
    out_tagoff(color);
  return 0;
}

//---------------------------------------------------------------------------
uchar out_index(ushort index, fmt_t mode, color_t color, uchar as_index)
{
  if ( as_index )
  {
    if ( !(idpflags & (IDM_BADIDXSTR | IDM_OUTASM))   // no store in file
      || !is_valid_string_index(index) )
    {
      return putShort(index);
    }
    color = COLOR_ERROR;
    mode = fmt_string;
  }
  return OutUtf8(index, mode, color);
}

//--------------------------------------------------------------------------
uchar out_alt_ind(uint32 val)
{
  if ( (ushort)val )
    return OutUtf8((ushort)val, fmt_fullname, COLOR_IMPNAME);
  return putShort((ushort)(val >> 16));
}

//--------------------------------------------------------------------------
// special label format/scan procedures
//--------------------------------------------------------------------------
void out_method_label(uchar is_end)
{
  gl_xref = gl_comm = 1;
  printf_line(0, COLSTR("met%03u_%s%s", SCOLOR_CODNAME), curSeg.id.Number,
              is_end ? "end" : "begin", COLSTR(":", SCOLOR_SYMBOL));
}

//---------------------------------------------------------------------------
static char putMethodLabel(ushort off)
{
  char str[32];
  int len = qsnprintf(str, sizeof(str), "met%03u_%s", curSeg.id.Number,
                      off ? "end" : "begin");

  if ( !checkLine(len) )
    return 1;
  out_tagon(COLOR_CODNAME);
  outLine(str, len);
  out_tagoff(COLOR_CODNAME);
  return 0;
}

//--------------------------------------------------------------------------
// procedure for get_ref_addr
int check_special_label(const char *buf, int len)
{
  if ( (uint)len >= sizeof("met000_end")-1
    && (*(uint32*)buf & 0xFFFFFF) == ('m'|('e'<<8)|('t'<<16)) )
  {

    switch ( *(uint32*)&buf[len -= 4] )
    {
      case ('_'|('e'<<8)|('n'<<16)|('d'<<24)):
        break;
      case ('e'|('g'<<8)|('i'<<16)|('n'<<24)):
        if ( (uint)len >= sizeof("met000_begin")-1 - 4
          && *(ushort*)&buf[len -= 2] == ('_'|('b'<<8)) )
        {
          break;
        }
        //PASS THRU
      default:
        len |= -1; // as flag
        break;
    }
    if ( (uint)len <= sizeof("met00000")-1 )
    {
      uint32 off = curSeg.CodeSize;
      if ( buf[len+1] == 'b' )
        off &= 0;
      uint n = 0, j = sizeof("met")-1;
      while ( true )
      {
        if ( !qisdigit((uchar)buf[j]) )
          break;
        n = n*10 + (buf[j] - '0');
        if ( ++j == len )
        {
          if ( n >= 0x10000 || (ushort)n != curSeg.id.Number )
            break;
          return (int)off;
        }
      }
    }
  }
  return -1;
}

//--------------------------------------------------------------------------
// end of special-label procedures
//----------------------------------------------------------------------
uchar outOffName(ushort off)
{
  if ( !off || off == curSeg.CodeSize )
    return putMethodLabel(off);
  if ( off < curSeg.CodeSize )
  {
    uchar err = 0;
    if ( outName(curSeg.startEA + curSeg.CodeSize, 0,
                 curSeg.startEA, off, &err) )
      return 0; // good
    if ( err )
      return 1; // bad
  }
  return putShort(off, 0);
}

//----------------------------------------------------------------------
bool block_begin(uchar off)
{
  return MakeLine(COLSTR("{", SCOLOR_SYMBOL), off);
}

//----------------------------------------------------------------------
bool block_end(uint32 off)
{
  return MakeLine(COLSTR("}", SCOLOR_SYMBOL), off);
}

//----------------------------------------------------------------------
bool block_close(uint32 off, const char *name)
{
  if ( !jasmin() )
    return block_end(off);
  return printf_line(off, COLSTR(".end %s", SCOLOR_KEYWORD), name);
}

//----------------------------------------------------------------------
bool close_comment(void)
{
  return MakeLine(COLSTR("*/", SCOLOR_AUTOCMT), 0);
}

//---------------------------------------------------------------------------
uchar out_nodelist(uval_t nodeid, uchar pos, const char *pref)
{
  netnode node(nodeid);
  uval_t cnt = node.altval(0);
  if ( cnt == 0 )
    DESTROYED("out::nodelist");

  uval_t off = 0;
  if ( pref ) // jasmin
  {
    if ( change_line() )
    {
bad:
      return 0;
    }
    off = strlen(pref);
  }

  for ( uint i = 0; ;  )
  {
    if ( pref ) // jasmin (single directive per line)
    {
      curpos = pos;
      out_keyword(pref);
      outcnt = off;
    }
    else if ( i && chkOutSymSpace(',') )
    {
      goto bad; // prompted list
    }
    if ( out_alt_ind((uint32)node.altval(++i)) )
      goto bad;
    if ( i >= cnt )
      return 1;
    if ( pref && change_line() )
      goto bad; // jasmin
  }
}

//----------------------------------------------------------------------
void init_prompted_output(char str[MAXSTR*2], uchar pos)
{
  maxpos = inf.margin;
//  if ( maxpos < 32 )
//    maxpos = 32;
//  if ( maxpos > MAXSTR - 4 )
//    maxpos = MAXSTR - 4;

#ifdef __debug__
  if ( debugmode == -1
    && inf.s_showpref && inf.margin == 77 && !inf.binSize )
  {
    maxpos -= gl_psize;
  }
#endif
  g_bufbeg  = str;
  g_bufsize = (MAXSTR*2) - STR_PRESERVED;
  init_output_buffer(g_bufbeg, g_bufsize);
  curpos = pos;
  outcnt = 0;
}

//----------------------------------------------------------------------
void term_prompted_output(void)
{
  init_output_buffer(NULL, 0);
  g_bufbeg = NULL;
  g_bufsize = 0;
  maxpos = 0;
  curpos = -1;
}

//----------------------------------------------------------------------
uchar OutConstant(op_t& x, uchar impdsc)
{
  uchar savetype = x.dtyp;
  fmt_t fmt = fmt_dscr;
  color_t color;

  switch ( (uchar)x.cp_type )
  {
    default:
      warning("OC: bad constant type %u", (uchar)x.cp_type);
      break;

    case CONSTANT_Long:
      x.dtyp = dt_qword;
      goto outNum;
    case CONSTANT_Double:
      x.dtyp = dt_double;
      goto outNum;
    case CONSTANT_Integer:
      x.dtyp = dt_dword;
      goto outNum;
    case CONSTANT_Float:
      x.dtyp = dt_float;
outNum:
      if ( putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
        break;
badconst:
      return 0;

    case CONSTANT_String:
      if ( OutUtf8(x._name, fmt_string, COLOR_STRING) )
        goto badconst;
      break;

    case CONSTANT_Class:
      CASSERT((fmt_cast+1) == fmt_classname && (fmt_classname+1) == fmt_fullname);
      {
        fmt_t f2 = (fmt_t )x.addr_shorts.high;
        color_t c2 = f2 < fmt_cast || f2 > fmt_fullname ? COLOR_KEYWORD
                   : cmd.xtrn_ip == 0xFFFF ? COLOR_DNAME : COLOR_IMPNAME;

        if ( OutUtf8(x._name, f2, c2) )
          goto badconst;
      }
      break;

    case CONSTANT_InterfaceMethodref:
    case CONSTANT_Methodref:
        fmt = fmt_retdscr;
    case CONSTANT_Fieldref:
#ifdef VIEW_WITHOUT_TYPE
        if ( impdsc )
#endif
          if ( !jasmin() && OutUtf8(x._dscr, fmt, COLOR_KEYWORD) )
            goto badconst;
        color = x._class == curClass.This.Dscr ? COLOR_DNAME : COLOR_IMPNAME;
        out_tagon(color);
        if ( jasmin() || (color == COLOR_IMPNAME && !impdsc) ) // other class
        {
          if ( OutUtf8(x._name, fmt_classname) || chkOutDot() )
            goto badconst;
        }
        if ( OutUtf8(x._subnam, fmt_name) )
          goto badconst; // Field
        out_tagoff(color);
        if ( jasmin() )
        {
          if ( fmt == fmt_retdscr )
            fmt = fmt_signature; // no space at end
          else if ( chkOutSpace() )
            goto badconst;
        }
        else
        {
          if ( fmt != fmt_retdscr )
            break;
          fmt = fmt_paramstr;
        }
        if ( OutUtf8(x._dscr, fmt, COLOR_KEYWORD) )
          goto badconst;
        break;
  }
  x.dtyp = savetype;
  return 1;
}

//--------------------------------------------------------------------------
void myBorder(void)
{
  MakeNull();
  if ( user_limiter )
  {
    inf.s_limiter = LMT_THIN;
    MakeBorder();
  }
  inf.s_limiter = 0;  // fo not output border between method & vars :(
}

//--------------------------------------------------------------------------
uchar out_problems(char str[MAXSTR], const char *prefix)
{
  if ( curClass.extflg & XFL_C_ERRLOAD )
  {
    myBorder();
    printf_line(inf.indent,
                COLSTR("%s This class has had loading time problem(s)", SCOLOR_ERROR),
                prefix);
    if ( curClass.msgNode )
    {
      MakeNull();
      if ( print_loader_messages(str, prefix) == -1 )
        return 1;
    }
    myBorder();
  }
  return 0;
}

//--------------------------------------------------------------------------
uchar putScope(ushort scope, uint32 doff)
{
  if ( !scope || scope == curSeg.CodeSize )
    return putMethodLabel(scope);

  if ( scope < curSeg.CodeSize )
  {
    uchar err = 0;
    if ( outName(curSeg.DataBase + doff, 0, curSeg.startEA, scope, &err) )
      return 0;
    if ( err )
      return 1;
  }

  return putShort(scope, 0);
}

//----------------------------------------------------------------------
size_t debLine(void)
{
  OutChar('"');
  out_tagoff(COLOR_STRING);
  if ( change_line() )
    return 0;
  return putDeb(1);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t& x)
{
  int outf;
  uchar warn = 0;

  switch ( x.type )
  {
    case o_near:
      if ( x.ref )
      {
        ++warn;
      }
      else
      {
        if ( outName(cmd.ea + x.offb, x.n, curSeg.startEA, x.addr, &warn) )
          break;
        if ( warn )
          goto badop;
      }
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32, warn) )
        break;
      //PASS THRU
    case o_void:
badop:
      return false;

    case o_imm:
      if ( x.ref == 2 )
        ++warn;
      outf = OOFW_IMM | OOF_NUMBER | (x.ref ? OOFS_NOSIGN : OOF_SIGNED);
      if ( putVal(x, outf, warn) )
        break;
      goto badop;

    case o_mem:
      if ( jasmin() )
        goto putVarNum;
      if ( x.ref )
      {
putAddr:
        ++warn;
      }
      else
      {
        if ( outName(cmd.ea + x.offb, x.n, curSeg.DataBase, x.addr, &warn) )
          break;
        if ( warn )
          goto badop;
      }
putVarNum:
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16, warn) )
        break;
      goto badop;

    case o_cpool:
      if ( !x.cp_ind)
      {
        OUT_KEYWORD("NULL" );
      }
      else
      {
        if ( x.ref )
          goto putAddr;
        if ( !OutConstant(x) )
          goto badop;
      }
      break;

    case o_array:
      if ( !x.ref )
      {
        int i = (uchar)x.cp_type - (T_BOOLEAN-1); // -1 - correct tp_decl
        if ( i < 0 || i > T_LONG - (T_BOOLEAN-1) )
          goto badop;
        if ( chkOutKeyword(tp_decl[i].str, tp_decl[i].size) )
          goto badop;
      }
      else
      {
        static const char tt_bogust[] = "BOGUST_TYPE-";

        if ( !checkLine(sizeof(tt_bogust) + 2) )
          goto badop;
        out_tagon(COLOR_ERROR);
        outcnt += out_snprintf("%c%s%u", WARN_SYM, tt_bogust, (uchar)x.cp_type);
        out_tagoff(COLOR_ERROR);
      }
      break;

    default:
      warning("out: %a: bad optype %d", cmd.ip, x.type);
      break;
  }
  return true;
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  if ( !jasmin() )
    block_end(0);
}
