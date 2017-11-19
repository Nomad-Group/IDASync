/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "java.hpp"
#include "oututil.hpp"

// support for jasmin reserved word's
#define QS(f) (fmt_t)(f | FMT_ENC_RESERVED)

//----------------------------------------------------------------------
static bool out_sm_end(void)
{
  return block_close(4, "stack");
}

//----------------------------------------------------------------------
static bool out_deprecated(uchar pos)
{
  return MakeLine(COLSTR(".deprecated", SCOLOR_KEYWORD), pos);
}

//----------------------------------------------------------------------
static bool out_sm_start(int same)
{
  char samestr[80];

  samestr[0] = 0;
  if ( same >= 0 )
  {
    char tmp[32];
    tmp[0] = '\0';
    if ( same )
      qsnprintf(tmp, sizeof(tmp), COLSTR(" %d", SCOLOR_NUMBER), same);
    qsnprintf(samestr, sizeof(samestr), " use%s locals", tmp);
  }

  if ( jasmin() )
    return printf_line(4, COLSTR(".stack%s", SCOLOR_KEYWORD), samestr);

  return printf_line(4,
                     COLSTR("%s %s StackMap%s", SCOLOR_AUTOCMT),
                     COLSTR("{", SCOLOR_SYMBOL),
                     ash.cmnt, samestr);
}

//----------------------------------------------------------------------
static bool out_stackmap(const SMinfo *pinf)
{
  static char const *const verif[ITEM_BADOBJECT] =
  {
    "Top", "Integer", "Float", "Double", "Long", "Null", "UninitializedThis",
    "Object ", "Unititialized "
  };
  static char const *const kwd[3] = { "locals", "stack", NULL };

  union
  {
    const uchar   *p1;
    const ushort  *p2;
  };

  char const *const *stage;
  uchar rectype;
  uint vcnt;

  p1 = pinf->pb;
  rectype = SMT_FULL_FRAME;
  if ( SMF_mode )
    rectype = *p1++; // >=JDK6
  if ( rectype >= SMT_SAME_FRM_S1 )
    ++p2;  // skip offset
  if ( (rectype < SMT_SAME_FRM_S1 && rectype > SMT_SAME_FRM_S1_max) )
    goto BADIDB;
  if ( p1 > pinf->pe )
    goto BADIDB;

  {
    int hdr = -1;

    if ( rectype != SMT_FULL_FRAME )
    {
      ++hdr;  // 0 -- without args
      if ( rectype >= SMT_CHOP_FRM_S0_min && rectype <= SMT_CHOP_FRM_S0_max )
      {
        hdr = SMT_SAME_FRM_S0 - rectype;
        if ( (uint)hdr > pinf->fcnt )
          goto BADIDB;
        hdr = pinf->fcnt - hdr;
        if ( hdr == 0 )
          --hdr;  // nocopy
      }
    }
    if ( out_sm_start(hdr) )
      goto STOP_NOW;
  }

  if ( pinf->ea != cmd.ea )
    if ( printf_line(6, COLSTR("%s %u", SCOLOR_ERROR),
                    COLSTR("offset", SCOLOR_KEYWORD),
                    (uint)(pinf->ea - curSeg.startEA)) )
      goto STOP_NOW;


  if ( rectype <= SMT_SAME_FRM_S0_max )
    goto done_block;
  stage = &kwd[1];
  vcnt  = 1;
  if ( rectype > SMT_SAME_FRM_S1 )
  {
    if ( rectype <= SMT_SAME_FRM_S0 )
      goto done_block;
    --stage;
    if ( rectype != SMT_FULL_FRAME )
    {
      vcnt = rectype - SMT_SAME_FRM_S0;
    }
    else
    {
repeat_stage:
      vcnt = *p2++;
      if ( p1 > pinf->pe )
        goto BADIDB;
    }
  }
  if ( vcnt != 0 )
  {
    do
    {
      uchar tag = *p1++;
      if ( p1 > pinf->pe || tag > ITEM_CURCLASS )
        goto BADIDB;
      curpos = 6;
      out_tagon(COLOR_KEYWORD);
      outcnt = out_snprintf("%s %s", *stage,
                            verif[tag < ITEM_BADOBJECT ? tag : ITEM_Object]);
      out_tagoff(COLOR_KEYWORD);
      CASSERT((ITEM_Object+1) == ITEM_Uninitialized
           && (ITEM_Uninitialized+1) == ITEM_BADOBJECT
           && (ITEM_BADOBJECT+1) == ITEM_CURCLASS);
      if ( tag >= ITEM_Object )
      {
        ushort var = *p2++;
        if ( p1 > pinf->pe )
          goto BADIDB;
        switch ( tag ) {
          case ITEM_BADOBJECT:
            if ( putShort(var) )
              goto STOP_NOW;
            break;
          case ITEM_CURCLASS:
          case ITEM_Object:
            if ( OutUtf8(var,
                         QS(fmt_fullname),
                         tag == ITEM_Object ? COLOR_IMPNAME : COLOR_DNAME) )
              goto STOP_NOW;
            break;
          case ITEM_Uninitialized:
            if ( outOffName(var) )
              goto STOP_NOW;
            break;
        }
      }
      if ( change_line() )
        goto STOP_NOW;
    }
    while ( --vcnt );
  }
  if ( rectype == SMT_FULL_FRAME && *++stage )
    goto repeat_stage;
done_block:
  if ( p1 == pinf->pe )
    return out_sm_end();
BADIDB:
  DESTROYED("out_stackmap");
STOP_NOW:
  return true;
}

//----------------------------------------------------------------------
static uchar OutModes(uint32 mode)
#define OA_THIS   0
#define OA_FIELD  1
#define OA_METHOD 2
#define OA_NEST   4 // in this case low BYTE == OA_NEST, hi word == access
{
  static const TXS fn[] =
  {
    TXS_DECLARE("public "),
    TXS_DECLARE("private "),
    TXS_DECLARE("protected "),
    TXS_DECLARE("static "),
    TXS_DECLARE("final "),
    TXS_DECLARE("synchronized "), // "super "   (file)
    TXS_DECLARE("volatile "),     // "bridge "  (method)
    TXS_DECLARE("transient "),    // "varargs " (method)
    TXS_DECLARE("native "),
    TXS_EMPTY(),  // "interface " // special output mode
    TXS_DECLARE("abstract "),
    TXS_DECLARE("fpstrict "),     // float-ing-point FP-stricted
    TXS_DECLARE("synthetic "),    // create by compiler (not present in source)
    TXS_DECLARE("annotation "),
    TXS_DECLARE("enum ")          // class or it superclass is enum
  };

  static const TXS ex[2] =
  {
    TXS_DECLARE("bridge "),
    TXS_DECLARE("varargs ")
  };

  static const TXS kwd[4] =
  {
    TXS_DECLARE(".class "),
    TXS_DECLARE(".field "),
    TXS_DECLARE(".method "),
    TXS_DECLARE(".interface ")
  };

  ushort access_mode;
  uchar off = 2, flg;
  int kwdo;

  switch ( mode )
  {
    case OA_FIELD:
      flg = curField.id.extflg;
      access_mode = curField.id.access & ACC_FIELD_MASK;
      break;
    case OA_METHOD:
      flg = curSeg.id.extflg;
      access_mode = curSeg.id.access & ACC_METHOD_MASK;
      break;
    case OA_THIS:
      flg = curClass.extflg;
      access_mode = curClass.AccessFlag & ACC_THIS_MASK;
      off    = 0;
      break;
    default:  // OA_NEST
      flg = 0;
      access_mode = (ushort)(mode >> 16);
      break;
  }

  kwdo = mode & 3;
  if ( kwdo == 0 && (access_mode & ACC_INTERFACE) )
    kwdo += 3;

  if ( !jasmin() && (flg & XFL_DEPRECATED) )
  {
    out_commented("@Deprecated", COLOR_AUTOCMT);
    if ( change_line() )
    {
BADIDB:
      return 1;
    }
    curpos = off;
  }

  if ( mode >= OA_NEST && !jasmin() )
  {
    outcnt += out_commented("{Inner}: ");
  }
  else
  {
    out_tagon(COLOR_KEYWORD);
    uint rc = 0;
    if ( jasmin() )
    {
      if ( mode >= OA_NEST )
      {
        OUT_STR(".inner ");
        ++rc;
      }
      outLine(&kwd[kwdo].str[rc], kwd[kwdo].size-rc);
    }
  }
  for ( uint m, v = access_mode & ((1 << qnumber(fn)) - 1), i = 0;
        (m = (1<<i)) <= v;
        i++ ) //lint !e440 for clause irregularity
  {
    if ( (v & m) == 0 )
      continue;

    const TXS *pfn = &fn[i];

    switch ( m )
    {
      case ACC_SUPER:
        if ( !(mode & 3) )
          continue; // OA_THIS, OA_NEST: 'super' is deprecated;
      default:
        break;
      case ACC_BRIDGE:
      case ACC_VARARGS:
        if ( (uchar)mode == OA_METHOD )
          pfn = &ex[m == ACC_VARARGS];
        break;
    }
    if ( !pfn->size )
      continue; // special case
    if ( chkOutLine(pfn->str, pfn->size) )
      goto BADIDB;
  }
  switch ( mode )
  {
    default:  // OA_NEST, OA_THIS
      if ( !jasmin()
        && chkOutLine(&kwd[kwdo].str[1], kwd[kwdo].size-1) )
      {
        goto BADIDB;
      }
      if ( (uchar)mode != OA_THIS && !jasmin() )
        break;
      // no break
    case OA_FIELD:
    case OA_METHOD:
      out_tagoff(COLOR_KEYWORD);
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
static uchar sign_out(ushort utsign, char mode)
{
  fmt_t fmt = fmt_string;

  if ( !jasmin() )
  {
    out_tagon(COLOR_AUTOCMT);
    outcnt += out_commented("User type: ");
    fmt = fmt_signature; // for field/locvar
    if ( mode )
    {
      fmt = fmt_prefsgn; // method
      if ( mode > 0 )
        fmt = fmt_clssign;  // defer for check ONLY
    }
  }
  else
  {
    static const TXS sgn = TXS_DECLARE(".signature ");
    out_tagon(COLOR_KEYWORD);
    if ( chkOutLine(sgn.str + !mode, sgn.size - !mode) )
      goto BADIDB;
  }
  if ( OutUtf8(utsign, fmt) )
  {
BADIDB:
    return 1;
  }
  if ( fmt == fmt_prefsgn )
  {
    if ( OutUtf8(utsign, fmt_retdscr)
      || chkOutSpace()
      || OutUtf8(utsign, fmt_paramstr)
      || OutUtf8(utsign, fmt_throws) )
    {
      goto BADIDB;
    }
  }
  out_tagoff(jasmin() ? COLOR_KEYWORD : COLOR_AUTOCMT);
  if ( mode || !jasmin() )
    return change_line();
  return chkOutSpace();
}

//----------------------------------------------------------------------
static void out_switch(void)
{
  op_t x;
  x.n     = 0;
  x.flags = OF_SHOW;
  x.dtyp  = dt_dword; //???  ’Ž   ???
  x.type  = o_imm;    //???  €„Ž  ???

  if ( !jasmin() && block_begin(4) )
    return;

  uchar nwarns = 0;
  uval_t count;
  ea_t addr;
  for ( addr = cmd.Op2.addr, count = cmd.Op3.value; count; addr += 4, count-- )
  {
    curpos = 8;
    if ( cmd.itype == j_lookupswitch )
    {
      x.value = get_long(curSeg.startEA + addr); // pairs
      addr += 4;
      if ( !putVal(x, OOFW_IMM | OOF_NUMBER | OOF_SIGNED | OOFW_32, 0)
        || chkOutSpace()
        || chkOutSymSpace(':') )
      {
        return;
      }
      if ( !checkLine(1 + 8 - ((outcnt + 1) % 8)) )
        return;
      int idx = outcnt & 7;
      if ( idx != 0 )
      {
        static const char seven_spaces[] = "       ";
        OutLine(&seven_spaces[idx-1]);
      }
    }
    x.value = cmd.ip + get_long(curSeg.startEA + addr);
    if ( x.value >= curSeg.CodeSize )
    {
      ++nwarns;
    }
    else
    {
      if ( outName(curSeg.startEA + addr, x.n, curSeg.startEA, x.value, &nwarns) )
        goto doneswitch;
      if ( nwarns )
        return;
    }
    if ( !putVal(x, OOFW_IMM | OOF_NUMBER | OOFS_NOSIGN | OOFW_32, nwarns) )
      return;
doneswitch:
    if ( change_line() )
      return;
  }
  curpos = 6;
  OUT_KEYWORD("default ");
  if ( chkOutSymSpace(':') || !outop(cmd.Op3) || change_line() )
    return;
  if ( !jasmin() )
    block_end(4);
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char str[MAXSTR*2];
  static const char *const addonce[] = { "", "_w", "_quick", "2_quick", "_quick_w" };

  getMySeg(cmd.ea); // set curSeg (for special strings)
  gl_xref = 0;

  if ( curSeg.smNode && !(idpflags & IDF_HIDESM) )
  {
    SMinfo smi;
    smi.ea = BADADDR;
    if ( sm_getinfo(&smi) )
    {
      init_prompted_output(str, 4);
      do
        if ( out_stackmap(&smi))
          goto STOP_NOW;
      while ( sm_getinfo(&smi) );
    }
  }

  init_prompted_output(str, 4);
  OutMnem(2, addonce[uchar(cmd.wid)]);
  out_zero();
  outcnt = tag_strlen(str);

  if ( cmd.Op1.type != o_void )
  {
    if ( !out_one_operand(0) )
      goto STOP_NOW;
  }
  else
  {
    if ( (char)cmd.Op1.ref > 0 && inf.s_showbads )
    {
      qstring nbuf;
      if ( get_visible_name(&nbuf, cmd.Op1.addr) > 0 )
        outcnt += out_commented(nbuf.begin(), COLOR_REGCMT);
    }
  }

  if ( cmd.Op2.type != o_void )
  {
    if ( chkOutSpace() )
      goto STOP_NOW;
    if ( cmd.itype == j_tableswitch && !jasmin() )
    {
      if ( CHK_OUT_KEYWORD("to ") )
        goto STOP_NOW;
    }
    if ( !out_one_operand(1) )
      goto STOP_NOW;
  }

  if ( cmd.Op3.type != o_void && !cmd.swit ) // ! lookupswitch/tablesswitch
  {
    if ( chkOutSpace() || !out_one_operand(2) )
      goto STOP_NOW;
  }

  gl_xref = gl_comm = 1;
  if ( !change_line(true) )
  {
    if ( cmd.swit & 2 )
      out_switch();  // normal tableswitch/lookupswitch
  }
STOP_NOW:
  term_prompted_output();
}

//--------------------------------------------------------------------------
static bool close_annotation(uint32 pos)
{
  return block_close(pos, "annotation");
}

//--------------------------------------------------------------------------
static const ushort *annotation_element(const ushort *ptr, uint *plen,
                                        uint pos, ushort name);

static const ushort *annotation(const ushort *p, uint *plen, uint pos)
{
  if ( *plen < sizeof(ushort) )
    return NULL;
  *plen -= sizeof(ushort);
  uint pairs = *p++;
  if ( pairs != 0 )
  {
    do
    {
      curpos = pos;
      if ( *plen < sizeof(ushort) )
        return NULL;
      *plen -= sizeof(ushort);
      p = annotation_element(p+1, plen, pos, *p);
      if ( p == NULL )
        break;
      if ( change_line() )
        goto STOP_NOW;
    }
    while ( --pairs );
  }
  return p;

STOP_NOW:
  *plen = (uint)-1;
  return NULL;
}

//--------------------------------------------------------------------------
static const ushort *annotation_element(
        const ushort *p,
        uint *plen,
        uint pos,
        ushort name)
{
  uchar tag = 0, type = 0;
  ushort val, prev = 0;
  int alev = 0;
  color_t ecol = COLOR_IMPNAME;
  const TXS *pt;
  const_desc_t co;

  op_t x;
  x.flags = 0;  // output flags, will be used by OutValue()
  x.n = 0;      // operand number, will be used by OutValue()
  do // array-values-loop
  {
arentry:
    if ( *plen < sizeof(uchar)+sizeof(ushort) )
      goto BADIDB;
    *plen -= sizeof(uchar)+sizeof(ushort);
    if ( alev > 0 && tag != *(uchar*)p )
      goto BADIDB;
    tag = *(uchar *)p;
    p = (ushort*)((uchar*)p+1);
    val = *p++;
    if ( tag == j_array )
    {
      if ( !*plen || (alev= val) == 0 || (tag= *(uchar*)p) == j_array )
        goto BADIDB;
      alev = -alev;
      goto arentry;
    }

    if ( alev > 0 ) // not first array element
    {
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( prev != val )
            goto BADIDB;
        default:
          break;
      }
      if ( !jasmin() )
      {
         if ( chkOutSymSpace(',') )
           goto STOP_NOW;
      }
      else if ( tag != j_annotation )
      {
         if ( chkOutSpace() )
           goto STOP_NOW;
      }
      else
      {
        if ( change_line() )
          goto STOP_NOW;
        curpos = pos;
      }
      goto do_value;
    }

    switch ( tag )
    {
      default:
        goto BADIDB;

      case j_annotation:
      case j_enumconst:
        if ( val == curClass.This.Dscr )
          ecol = COLOR_DNAME;
        prev = val;
        //PASS THRU
      case j_class_ret:
      case j_string:
        break;

      case j_float:
        type    = CONSTANT_Float;
        x.dtyp  = dt_float;
        break;
      case j_long:
        type    = CONSTANT_Long;
        x.dtyp  = dt_qword;
        break;
      case j_double:
        type    = CONSTANT_Double;
        x.dtyp  = dt_double;
        break;
      case j_bool:
      case j_byte:
      case j_char:
        x.dtyp = dt_byte;
        goto do_int;
      case j_short:
        x.dtyp = dt_word;
        goto do_int;
      case j_int:
        x.dtyp = dt_dword;
do_int:
        type = CONSTANT_Integer;
        break;
    }

    if ( jasmin() )
    {
      if ( name )
      {
        if ( OutUtf8(name, fmt_name, COLOR_DNAME) || chkOutSpace() )
          goto STOP_NOW;
      }
      out_tagon(COLOR_KEYWORD);
      if ( alev )
      {
        if ( !checkLine(2) )
          goto STOP_NOW;
        OutChar(j_array);
      }
      if ( chkOutChar(tag) )
        goto STOP_NOW;
      out_tagoff(COLOR_KEYWORD);
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( chkOutSpace() || OutUtf8(val, fmt_signature, ecol) )
            goto STOP_NOW;
        default:
          break;
      }
    }
    else
    { // jasmin
      static const TXS doptype[] =
      {
        TXS_DECLARE("String"),
        TXS_DECLARE("Enum"),
        TXS_DECLARE("Class"),
        TXS_DECLARE("Annotation")
      };
      pt = doptype;
      switch ( tag )
      {
        case j_annotation:
          ++pt;
          //PASS THRU
        case j_class_ret:
          ++pt;
          //PASS THRU
        case j_enumconst:
          ++pt;
          //PASS THRU
        case j_string:
          break;

        default:
          pt = get_base_typename(tag);
          if ( pt == NULL )
            goto BADIDB;
          break;
      }
      if ( chkOutKeyword(pt->str, pt->size) )
        goto STOP_NOW;
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( chkOutSpace() || OutUtf8(val, fmt_signature, ecol) )
            goto STOP_NOW;
        default:
          break;
      }
      if ( alev && CHK_OUT_KEYWORD("[]") )
        goto STOP_NOW;
      if ( name != 0 )
      {
        if ( chkOutSpace() || OutUtf8(name, fmt_name, COLOR_DNAME) )
          goto STOP_NOW;
      }
    } // jasmin
    alev = -alev;  // 0 = 0
/*
    if ( chkOutSpace() )
      goto STOP_NOW;
    if ( (name || jasmin()) && chkOutSymSpace('=') )
      goto STOP_NOW;
*/
    if ( chkOutSpace() || chkOutSymSpace('=') )
      goto STOP_NOW;
do_value:
    switch ( tag )
    {
      case j_annotation:
        if ( jasmin() )
        {
          if ( CHK_OUT_KEYWORD(".annotation") )
            goto STOP_NOW;
        }
        else
        {
          if ( chkOutSymbol('{') )
            goto STOP_NOW;
        }
        if ( change_line() )
          goto STOP_NOW;
        p = annotation(p, plen, pos+2);
        if ( p == NULL )
          goto done;
        curpos = pos;
        if ( jasmin() )
        {
          OutLine(COLSTR(".end annotation", SCOLOR_KEYWORD));
        }
        else
        {
          out_symbol('}');
          ++outcnt;
        }
        continue;

      case j_class_ret:
        if ( !OutUtf8(val, fmt_signature, // without space
                      val == curClass.This.Dscr ? COLOR_DNAME : COLOR_IMPNAME) )
          continue;
STOP_NOW:
        *plen = (uint)-1;
BADIDB:
        return NULL;

      case j_enumconst:
        if ( *plen < sizeof(ushort) )
          goto BADIDB;
        *plen -= sizeof(ushort);
        if ( OutUtf8(*p++, fmt_name, ecol) )
          goto STOP_NOW;
        continue;

      case j_string:
        if ( OutUtf8(val, fmt_string, COLOR_STRING) )
          goto STOP_NOW;
        continue;

      default:
        break;
    }
    if ( !LoadOpis(val, type, &co) )
      goto BADIDB;
    if ( !jasmin() )
    {
      switch(tag )
      {
        case j_bool:
          {
            static const TXS bt[2] =
            {
              TXS_DECLARE("true"),
              TXS_DECLARE("false")
            };
            pt = &bt[!co.value];
            if ( chkOutKeyword(pt->str, pt->size) )
              goto STOP_NOW;
          }
          continue;

        case j_char:
          if ( co.value < ' ' || co.value >= 0x80 )
            break;
          if ( !checkLine(3) )
            goto STOP_NOW;
          out_snprintf(COLSTR("'%c'", SCOLOR_CHAR), char(co.value));
          outcnt += 3;
          continue;

        default:
          break;
      }
    }
    copy_const_to_opnd(x, co);
    if ( !putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
      goto STOP_NOW;
  }
  while ( alev && --alev );
done:
  return p;
}

//--------------------------------------------------------------------------
static uchar annotation_loop(const uval_t *pnodes, uint nodecnt)
{
  uchar result = 1;
  uint32 pos = curpos;

  if ( MakeNull() )
    goto STOP_NOW;

  for ( uint n = 0; n < nodecnt; n++ )
  {
    if ( pnodes[n] )
    {
      static char const *const jnames[5] =
      {
        "visible", "invisible", "default", "visibleparam", "invisibleparam"
      };
      static char const *const lnames[5] =
      {
        "RuntimeVisible", "RuntimeInvisible",
        "Default",
        "RuntimeVisibleParameter", "RuntimeInvisibleParameter"
      };
      char hdr[MAXSTR];
      uint hdrpos, hdrlen, len;
      const ushort *p = (ushort*)get_annotation(pnodes[n], &len);
      if ( p == NULL )
        goto BADIDB;

      if ( jasmin() )
      {
        hdrpos = qsnprintf(hdr, sizeof(hdr),
                           COLSTR(".annotation %s", SCOLOR_KEYWORD),
                           jnames[n]);
      }
      else
      {
        hdrpos = qsnprintf(hdr, sizeof(hdr),
                           COLSTR("%sAnnotation", SCOLOR_KEYWORD),
                           lnames[n]);
      }

      if ( n == 2 ) // defalut
      {
        if ( !jasmin() )
          qstrncpy(&hdr[hdrpos], COLSTR(" {", SCOLOR_SYMBOL), sizeof(hdr)-hdrpos);
        if ( MakeLine(hdr, pos) )
          goto STOP_NOW;
        curpos = pos + 2;
        p = annotation_element(p, &len, pos+2, 0);
        if ( p == NULL )
        {
checkans:
          if ( len == (uint)-1 )
            goto STOP_NOW;
          goto BADIDB;
        }
        if ( len )
          goto BADIDB;
        if ( change_line() || close_annotation(pos) )
          goto STOP_NOW;
        continue;
      }
      int nump = 0, ip = 1;
      uchar present = 0;
      if ( n > 2 ) // parameters
      {
        --len;
        nump = *(uchar*)p;
        if ( nump == 0 )
          goto BADIDB;
        p = (ushort*)((uchar*)p+1);
        if ( !jasmin() )
          hdrpos += qsnprintf(&hdr[hdrpos], sizeof(hdr)-hdrpos,
                              COLSTR(" for parameter", SCOLOR_KEYWORD));
      }
      hdr[hdrpos++] = ' ';
      hdr[hdrpos] = '\0';
      do // parameters loop
      {
        if ( len < sizeof(ushort) )
          goto BADIDB;
        len -= sizeof(ushort);
        uint cnt = *p++;
        if ( !cnt )
        {
          if ( !nump )
            goto BADIDB;
          continue;
        }
        if ( nump )
          qsnprintf(&hdr[hdrpos], sizeof(hdr) - hdrpos, COLSTR("%d ", SCOLOR_NUMBER), ip);
        present = 1;
        hdrlen = (uint32)tag_strlen(hdr);
        do // annotations loop
        {
          if ( len < sizeof(ushort) )
            goto BADIDB;
          len -= sizeof(ushort);
          curpos = pos;
          OutLine(hdr);
          outcnt = hdrlen;
          if ( OutUtf8(*p, jasmin() ? fmt_signature : fmt_dscr) )
            goto STOP_NOW;
          if ( !jasmin() )
            out_symbol('{');
          if ( change_line() )
            goto STOP_NOW;
          p = annotation(p+1, &len, pos+2);
          if ( p == NULL )
            goto checkans;
          if ( close_annotation(pos) )
            goto STOP_NOW;
        }
        while ( --cnt );
      }
      while ( ++ip <= nump );
      if ( nump && !present )
        goto BADIDB;
      if ( len )
        goto BADIDB;
    }
  } // loop of annotation types
  result = 0;
STOP_NOW:
  return result;

BADIDB:
  DESTROYED("annotation");
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  char str[MAXSTR*2];

  if ( !jasmin() )
    MakeLine(COLSTR("/*", SCOLOR_AUTOCMT), 0 );
  const char *prefix = jasmin() ? ash.cmnt : "";

#ifdef __debug__
  printf_line(0, COLSTR("%sDisassembler mode: %s", SCOLOR_AUTOCMT),
              prefix, debugmode ? "DEBUG" : "Normal");
#endif
  printf_line(0,
              COLSTR("%sJava Virtual Machine (JDK 1.%u)", SCOLOR_AUTOCMT),
              prefix, curClass.JDKsubver);
  {
    char sv = inf.indent;
    inf.indent = 0;
    if ( !jasmin() )
    {
      printf_line(-1,
                  COLSTR("%sClassFile version: %u.%u", SCOLOR_AUTOCMT),
                  prefix, curClass.MajVers, curClass.MinVers);
    }
    else
    {
      if ( out_problems(str, prefix) )
        return;
      MakeNull();
      printf_line(-1, COLSTR("%s %u.%u", SCOLOR_NUMBER),
                  COLSTR(".bytecode", SCOLOR_KEYWORD),
                  curClass.MajVers, curClass.MinVers);
    }
    inf.indent = sv;
  }

  if ( curClass.SourceName )
  {
    init_prompted_output(str);
    if ( jasmin() )
    {
      OUT_KEYWORD(".source ");
      out_tagon(COLOR_STRING);
    }
    else
    {
      out_tagon(COLOR_AUTOCMT);
      OUT_STR("Source File      : ");
    }
    uchar stp;
    {
      uint32 save = idpflags;
      idpflags = (idpflags & ~IDF_AUTOSTR) | IDF_ENCODING;  // PARANOYA
      stp = OutUtf8(curClass.SourceName, fmt_string);
      idpflags = save;
    }
    if ( !stp )
      out_tagoff(jasmin() ? COLOR_STRING : COLOR_AUTOCMT);
    term_output_buffer();
    if ( stp || MakeLine(str, 0) )
      return;
  }
  else
  {
    MakeNull();
  }

  if ( !jasmin() )
  {
    if ( out_problems(str, prefix) )
      return;
    close_comment();
  }
  myBorder();
}

//--------------------------------------------------------------------------
static uchar enclose_out(void)
{
  if ( !jasmin() )
  {
    out_tagon(COLOR_AUTOCMT);
    outcnt += out_snprintf("%sEnclosing %s: ", ash.cmnt,
                           curClass.encMethod ? "method" : "class");
    out_tagon(COLOR_REGCMT);
  }
  else
  {
    OUT_KEYWORD(".enclosing method ");
  }
  if ( !curClass.encMethod )
  {
    if ( OutUtf8(curClass.encClass, QS(fmt_fullname)) )
      return 1;
  }
  else
  {
    const_desc_t op;

    if ( !LoadOpis(curClass.encMethod, CONSTANT_NameAndType, &op) )
      DESTROYED("out::enclose");
    if ( (!jasmin() && OutUtf8(op._name, fmt_retdscr))
      || OutUtf8(curClass.encClass, fmt_fullname)
      || chkOutChar(jasmin() ? '/' : '.')
      || OutUtf8(op._class, fmt_name)
      || OutUtf8(op._name, jasmin() ? fmt_dscr : fmt_paramstr) )
    {
      return 1;
    }
  }
  if ( !jasmin() )
    out_tagoff(COLOR_AUTOCMT);
  curpos = 0;
  return change_line();
}

//--------------------------------------------------------------------------
// output the method return type
static inline uchar out_seg_type(fmt_t fmt)
{
  return out_index(curSeg.id.dscr,
                   fmt,
                   COLOR_KEYWORD,
                   curSeg.id.extflg & EFL_TYPE);
}

//--------------------------------------------------------------------------
// output the field type
static inline uchar out_field_type(void)
{
  return out_index(curField.id.dscr,
                   fmt_dscr,
                   COLOR_KEYWORD,
                   curField.id.extflg & EFL_TYPE);
}

//--------------------------------------------------------------------------
size_t putDeb(uchar next)
{
  OUT_KEYWORD(".debug ");
  out_tagon(COLOR_STRING);
  if ( next )
    OutChar('"');
  return maxpos - outcnt;
}

//----------------------------------------------------------------------
static uchar out_includes(uval_t node, uchar pos)
{
  netnode temp(node);
  uint32 len, vid, cnt = (uint32)temp.altval(0);
  color_t color = jasmin() ? COLOR_KEYWORD : COLOR_AUTOCMT;
  char fnm[qmin(QMAXPATH,MAXSPECSIZE)+4];

  if ( !cnt )
    goto BADIDB;
  fnm[0] = '"';
  do {
    curpos = pos;

    len = (uint32)temp.supstr(cnt, &fnm[1], sizeof(fnm)-3);
    if ( !len )
      goto BADIDB;
    fnm[++len] = '"';
    fnm[++len] = '\0';
    char *pf = fnm;
    if ( idpflags & IDF_NOPATH )
    {
      pf = strrchr(pf, '/');
      if ( pf != NULL )
      {
        ++pf;
      }
      else
      {
#ifndef __UNIX__
        pf = &fnm[1+1];
        if ( *pf != ':' )
          --pf;
#else
        pf = &fnm[1];
#endif
      }
      *--pf = '"';
      len -= uint32(pf - fnm);
    }
    vid = (uint32)temp.altval(cnt);
    if ( vid == 0 || vid > curClass.maxCPindex )
      goto BADIDB;
    out_tagon(color);
    if ( jasmin() )
      OUT_STR(".attribute ");
    else
      outcnt = out_commented("GenericAttribute ");
    if ( OutUtf8((ushort)vid, fmt_name)
      || chkOutSpace()
      || chkOutLine(pf, len) )
    {
      goto STOP_NOW;
    }
    out_tagoff(color);
    if ( change_line() )
      goto STOP_NOW;
  }
  while ( --cnt );
  return 0;

BADIDB:
  DESTROYED("out_includes");
STOP_NOW:
  return 1;
}

//----------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  char str[MAXSTR*2];

  init_prompted_output(str, 2);

  gl_comm = 1;
  switch ( getMySeg(ea)->type ) // also set curSeg
  {
    case SEG_CODE:
      {
        func_t *pfn = get_func(ea);
        if ( pfn != NULL )
        {
          char *cmt = get_func_cmt(pfn, false);
          if ( cmt != NULL )
            cmt = get_func_cmt(pfn, true);
          if ( cmt != NULL )
          {
            bool ret = generate_big_comment(cmt, COLOR_REGCMT);
            qfree(cmt);
            if ( ret )
              break;
          }
        }
      }
      no_prim = true;
      if ( OutModes(OA_METHOD) )
        break;
      if ( !(curSeg.id.extflg & EFL_TYPE)
        && !jasmin()
        && out_seg_type(fmt_retdscr) )
      {
        break;
      }
      if ( out_index(curSeg.id.name, fmt_name, COLOR_CNAME,  // Method Name
                     curSeg.id.extflg & EFL_NAME) )
        break;
      if ( curSeg.id.extflg & EFL_TYPE )
      {
        if ( chkOutSpace() )
          break;
        goto do_dscid;
      }
      if ( jasmin() )
      {
do_dscid:
        if ( out_seg_type(fmt_dscr) )
          break;
      }
      else if ( OutUtf8(curSeg.id.dscr, fmt_paramstr, COLOR_KEYWORD) )
      {
        break;
      }
      if ( curSeg.thrNode )
      {
        const char *p = ".throws ";
        if ( !jasmin() )
        {
          if ( CHK_OUT_KEYWORD(" throws ") )
            break;
          p = NULL;
        }
        if ( !out_nodelist(curSeg.thrNode, 2, p) )
          break;
      }
      if ( change_line() )
        break;
      if ( curSeg.id.utsign )
      {
        curpos = 2;
        if ( sign_out(curSeg.id.utsign, -1) )
          break;
      }
      if ( jasmin() && (curSeg.id.extflg & XFL_DEPRECATED) )
      {
        if ( out_deprecated(2) )
          break;
      }
      if ( curSeg.genNodes[0] && out_includes(curSeg.genNodes[0], 2) )
        break;

      if ( curSeg.stacks
        && printf_line(2,
                       jasmin() ? COLSTR(".limit stack %u", SCOLOR_ASMDIR) :
                                  COLSTR("max_stack %u", SCOLOR_ASMDIR),
                       curSeg.stacks) )
      {
        break;
      }

      if ( curSeg.DataSize
        && printf_line(2,
                       jasmin() ? COLSTR(".limit locals %u", SCOLOR_ASMDIR) :
                                  COLSTR("max_locals %u", SCOLOR_ASMDIR),
                       curSeg.DataSize) )
      {
        break;
      }
      if ( (curSeg.id.extflg & XFL_M_EMPTYSM) && (out_sm_start(-1) || out_sm_end()) )
        break;

      if ( curSeg.id.extflg & XFL_M_LABSTART )
        out_method_label(0);
      if ( !jasmin() )
        block_begin(2);
      break;

    case SEG_IMP:
      curpos = 0;
      if ( OutModes(OA_THIS) )
        break;
      if ( out_index(curClass.This.Name, QS(fmt_fullname), COLOR_DNAME,
                   (uchar)!curClass.This.Dscr) )
        break;

      if ( jasmin() )
      {
        if ( !curClass.super.Ref )
          goto nosuper;
        if ( change_line(true) )
          break;
        OUT_KEYWORD(".super ");
      }
      else
      {
        uchar sskip = 0;
        if ( !curClass.super.Ref )
          goto check_imps;
        if ( (curClass.AccessFlag & ACC_INTERFACE)
          && (curClass.extflg & XFL_C_SUPEROBJ) )
        {
check_imps:
          if ( !curClass.impNode )
            goto noparents;
          sskip = 1;
        }

        if ( CHK_OUT_KEYWORD(" extends ") )
          break;
        if ( sskip )
          goto nosuper;
      }
      if ( out_alt_ind(curClass.super.Ref) )
        break;
nosuper:
      if ( curClass.impNode )
      {
        const char *p = ".implements ";
        if ( !jasmin() )
        {
          if ( curClass.AccessFlag & ACC_INTERFACE )
          {
            if ( curClass.super.Ref
              && !(curClass.extflg&XFL_C_SUPEROBJ)
              && chkOutSymSpace(','))
            {
              break;
            }
          }
          else if ( CHK_OUT_KEYWORD(" implements ") )
          {
            break;
          }
          p = NULL;
        }
        if ( !out_nodelist(curClass.impNode, 0, p) )
          break;
      }
noparents:
      if ( change_line(!jasmin()) )
        break;
      if ( curClass.utsign && sign_out(curClass.utsign, 1) )
        break;
      if ( curClass.encClass && enclose_out() )
        break;
      if ( jasmin() && (curClass.extflg & XFL_DEPRECATED) )
      {
        if ( out_deprecated(0) )
          break;
      }
      if ( curClass.genNode && out_includes(curClass.genNode, 0) )
        break;
      if ( (curClass.extflg & XFL_C_DEBEXT)
        && fmtString((ushort)-1, putDeb(0), fmt_debug, debLine) >= 0 )
      {
        out_tagoff(COLOR_STRING);
        change_line();
      }
      break;

    case SEG_XTRN:
    case SEG_BSS:
      if ( !jasmin() )
        MakeLine(COLSTR("/*", SCOLOR_AUTOCMT), 0);
    default:
      break;
  }
  term_prompted_output();
  no_prim = false;
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t ea)
{
  char str[MAXSTR*2];

  init_prompted_output(str, 4);
  str[0] = getMySeg(ea-1)->type; // also set curSeg
  switch ( str[0] )
  {
    case SEG_CODE:
      gl_name = 0;              // for empty method's
      if ( curSeg.id.extflg & XFL_M_LABEND )
        out_method_label(1);
      if ( curSeg.excNode )
      {
        netnode enode(curSeg.excNode);
        uint j = (uint32)enode.altval(0);
        if ( j == 0 )
          DESTROYED("out::segend" );

        if ( !jasmin())
          MakeLine(COLSTR("/*", SCOLOR_AUTOCMT), 0); /*"*///  makedep BUG!!!
        else
          MakeNull();
        uint i = 0;
        do
        {
          Exception ex;
          if ( enode.supval(++i, &ex, sizeof(ex)) != sizeof(ex) )
            DESTROYED("out::except");

          curpos = 4; // for loop with large lines
          if ( !jasmin() )
          {
            OUT_KEYWORD("try");
          }
          else
          {
            OUT_KEYWORD(".catch ");
            CASSERT(offsetof(Exception, filter.Ref)  == offsetof(Exception, filter.Name)
                 && offsetof(Exception, filter.Dscr) == offsetof(Exception, filter.Name) + 2);
            if ( !ex.filter.Ref )
              OUT_KEYWORD("all");
            else if ( out_alt_ind(ex.filter.Ref) )
              goto STOP_NOW;
          }
          {
            static const TXS kw[3] =
            {
              TXS_DECLARE(" from "),
              TXS_DECLARE(" to "),
              TXS_DECLARE(" using ")
            };
            int n = 0;
            do
            {
              if ( n == 2 && !jasmin() )
              {
                if ( ex.filter.Ref )
                {
                  if ( CHK_OUT_KEYWORD(" catch")
                    || chkOutSymbol('(')
                    || out_alt_ind(ex.filter.Ref)
                    || chkOutSymbol(')') )
                  {
                    goto STOP_NOW;
                  }
                }
                else
                {
                  if ( CHK_OUT_KEYWORD(" finally") )
                    goto STOP_NOW;
                }
                if ( CHK_OUT_KEYWORD(" handler ") )
                  goto STOP_NOW;
              }
              else
              {
                if ( chkOutKeyword(kw[n].str, kw[n].size) )
                  goto STOP_NOW;
              }
              CASSERT(offsetof(Exception,end_pc)-offsetof(Exception,start_pc) == sizeof(ushort)
                   && offsetof(Exception,handler_pc)-offsetof(Exception,end_pc) == sizeof(ushort));
              ushort off;
              switch ( n )
              {
                case 0: off = ex.start_pc;   break;
                case 1: off = ex.end_pc;     break;
                case 2: off = ex.handler_pc; break;
              }
              if ( outOffName(off) )
                goto STOP_NOW;
            }
            while ( ++n < 3 );
          }
          if ( change_line() )
            goto STOP_NOW;
        }
        while ( i < j );
        if ( !jasmin() )
          close_comment();
        else
          MakeNull();
      }
      if ( curSeg.genNodes[1] && out_includes(curSeg.genNodes[1], 2) )
        goto STOP_NOW;
      if ( curSeg.DataSize )
        goto STOP_NOW;
close_method:
      for(int i = 0; i < qnumber(curSeg.annNodes); i++)
      {
        if ( curSeg.annNodes[i] )
        {
          if ( annotation_loop(curSeg.annNodes, qnumber(curSeg.annNodes)) )
            goto STOP_NOW;
          MakeNull();
          break;
        }
      }
      block_close(2, "method");
      break;

//    case SEG_IMP:
    default:  // PARANOYA
      break;

    case SEG_XTRN:
    case SEG_BSS:
      if ( !jasmin() )
        close_comment();
      if ( str[0] == SEG_BSS )
        goto close_method;
      break;
  }
  myBorder();
STOP_NOW:
  term_prompted_output();
}

//--------------------------------------------------------------------------
void idaapi java_data(ea_t ea)
{
  char str[MAXSTR*2];
  char nbuf[MAXSTR];
  qstring name;
  op_t x;
  uint32 off;
  uint32 lvc;

  gl_name = 1;
  init_prompted_output(str);
  char stype = getMySeg(ea)->type; // also set curSeg
  ea_t ip = ea - curSeg.startEA;
  asize_t sz = get_item_size(ea) - 1;
  switch ( stype )
  {
    case SEG_CODE:
      if ( ip >= curSeg.CodeSize )
        goto STOP_NOW;
      if ( get_true_name(NULL, ea) > 0 )
        MakeLine(" ");  //for string delimeter
      if ( sz != 0 )
      {
illcall:
        OutLine(COLSTR("!!!_UNSUPPORTED_OUTPUT_MODE_!!!", SCOLOR_ERROR));
      }
      else
      {
        curpos = 2;
        uchar c = get_byte(ea);
        out_snprintf(COLSTR("%3u %s 0x%02X", SCOLOR_ERROR),
                     c, ash.cmnt, c);
      }
    default:
      break;

    case SEG_BSS:
      if ( isAlign(get_flags_novalue(ea)) )
      {
        gl_name = gl_comm = gl_xref = 0;
        goto STOP_NOW;
      }
      lvc = 0;  // unification
      off = uint32(ea - curSeg.DataBase);
      if ( (uint32)off >= (uint32)curSeg.DataSize )
      {
        off = (uint32)-1;
      }
      else if ( curSeg.varNode
             && (lvc = (uint32)netnode(curSeg.varNode).altval(off)) != 0 )
      {
        if ( (int32)lvc < 0 )
        {
          lvc = -(int32)lvc;
          if ( sz )  // can be byte for 'overloaded' variables :(
          {
            if ( --sz )
              goto BADIDB; // must be word
          }
        }
        if ( (lvc % sizeof(LocVar)) || lvc >= sizeof(nbuf) )
          goto BADIDB;
      }
      if ( jasmin() )
        out_line(ash.cmnt, COLOR_AUTOCMT);
      gl_name = 0;
      if ( off == (uint32)-1 )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      if ( get_visible_name(&name, ea) > 0 )
        out_snprintf(COLSTR("%s", SCOLOR_AUTOCMT), name.begin());
      if ( lvc == 0 )
        break;
      gl_xref = gl_comm = 1;
      if ( change_line() )
        goto STOP_NOW;
      if ( netnode(curSeg.varNode).supval(off, nbuf, lvc+1) != lvc )
        goto BADIDB;
      lvc /= sizeof(LocVar);
      for ( LocVar *plv = (LocVar*)nbuf; ; plv++ )
      {
        if ( jasmin() )
        {
          curpos = 4;
          OUT_KEYWORD(".var ");
          out_tagon(COLOR_NUMBER);
          outcnt += out_snprintf("%u", off);
          out_tagoff(COLOR_NUMBER);
          OUT_KEYWORD(" is ");
        }
        else
        {
          if ( plv->utsign && sign_out(plv->utsign, 0) )
            break;
          if ( OutUtf8(plv->var.Dscr, fmt_dscr, COLOR_KEYWORD) )
            break;
          if ( chkOutSpace() )
            break;
        }
        if ( OutUtf8(plv->var.Name, QS(fmt_name), COLOR_DNAME) )
          break;
        if ( chkOutSpace() )
          break;
        if ( jasmin() )
        {
          if ( OutUtf8(plv->var.Dscr, fmt_dscr, COLOR_KEYWORD) )
            break;
          if ( plv->utsign && sign_out(plv->utsign, 0) )
            break;
          if ( CHK_OUT_KEYWORD("from ") )
            break;
        }
        else
        {
          out_tagon(COLOR_AUTOCMT);
          if ( !out_commented("Scope: ") )
            break;
        }
        if ( putScope(plv->ScopeBeg, off) )
          break;
        if ( jasmin() )
        {
          if ( CHK_OUT_KEYWORD(" to ") )
            break;
        }
        else
        {
          if ( CHK_OUT_STR(" / ") )
            break;
        }
        if ( putScope(plv->ScopeTop, off) )
          break;
        if ( !jasmin() )
          out_tagoff(COLOR_AUTOCMT);
        if ( change_line(curpos != 0) || !--lvc )
          break;
      }
      goto STOP_NOW;

    case SEG_XTRN:
      if ( ip > (uint32)curClass.xtrnCnt )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      if ( !ip )
      {
        printf_line(0, COLSTR("%s Importing prototypes", SCOLOR_AUTOCMT),
                    jasmin() ? ash.cmnt : "");
        break; // equivalence - MakeNull(); with comment
      }

      if ( jasmin() )
      {
        out_snprintf(COLSTR("%s", SCOLOR_AUTOCMT), ash.cmnt);
        outcnt = strlen(ash.cmnt);
      }
      gl_name = gl_xref = gl_comm = 0;
      {
        const_desc_t co;
        {
          uint j = (uint32)XtrnNode.altval(ip);
          if ( j == 0 )
            goto BADIDB;
          if ( !LoadOpis((ushort)j, 0, &co) )
            goto BADIDB;
        }
        copy_const_to_opnd(x, co); // name / class & dscr / subnam
        x.ref = 0;  // as flag
        x.cp_type = co.type;
        switch ( x.cp_type )
        {
          default:
            goto BADIDB;

          case CONSTANT_Class:
            if ( !jasmin() )
            {
              set_output_ptr(str);
              outcnt = 0;
            }
            {
              static const TXS imp = TXS_DECLARE(".import ");
              int of = !jasmin();
              OutKeyword(imp.str+of, imp.size-of);
            }

            if ( !(co.flag & (HAS_TYPEDSCR | HAS_CLSNAME)) )
              goto do_idx_out;
            x.addr_shorts.high = (ushort)((co.flag & HAS_CLSNAME) ?
                                           fmt_fullname : fmt_classname);
            goto no_space_check;

          case CONSTANT_Fieldref:
            if ( (co.flag & NORM_FIELD) != NORM_FIELD )
              goto do_idx;
            break;
          case CONSTANT_InterfaceMethodref:
          case CONSTANT_Methodref:
            if ( (co.flag & NORM_METOD) != NORM_METOD )
            {
do_idx:
              ++x.ref;
            }
            break;
        }
      }
      if ( CHK_OUT_STR("  ") )
        goto STOP_NOW;
      if ( x.ref )
      {
do_idx_out:
        x.n = 2;
        if ( !putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16, 1) )
          goto STOP_NOW;
      }
      else
      {
no_space_check:
        if ( !OutConstant(x, 1) )
          goto STOP_NOW;
      }
//      if ( x.cp_type == CONSTANT_Class && !jasmin() )
//        out_line(".*", COLOR_SYMBOL);
      break;

    case SEG_IMP:
      if ( ip > (uint32)curClass.FieldCnt )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      gl_name = gl_comm = gl_xref = 0;
      if ( !ip )
      {
        if ( curClass.annNodes[0] | curClass.annNodes[1] )
        {
          if ( annotation_loop(curClass.annNodes, qnumber(curClass.annNodes)) )
            goto STOP_NOW;
        }
        if ( !jasmin() )
          block_begin(0);
        else
          MakeNull();

        if ( curClass.innerNode )
        {
          netnode inode(curClass.innerNode);
          uint j = (uint32)inode.altval(0);
          if ( j == 0 )
            goto BADIDB;
          color_t ci = jasmin() ? COLOR_IMPNAME : COLOR_NONE;
          uint i = 0;
          do
          {
            InnerClass ic;
            if ( inode.supval(++i, &ic, sizeof(ic)) != sizeof(ic) )
              goto BADIDB;
            curpos = 2;
            if ( !jasmin() )
              out_tagon(COLOR_AUTOCMT);
            if ( OutModes((((uint32)ic.access) << 16) | OA_NEST) )
              break;
            if ( ic.name )
            {
              if ( OutUtf8(ic.name, fmt_name, ci) )
                break;
            }
            else if ( !jasmin() && CHK_OUT_STR("{anonymous}") )
            {
              break;
            }
            if ( ic.inner )
            {
              if ( jasmin() )
              {
                if ( CHK_OUT_KEYWORD(" inner ") )
                  break;
              }
              else if ( CHK_OUT_STR(" {is}: ") )
              {
                break;
              }
              if ( OutUtf8(ic.inner, fmt_fullname, ci) )
                break;
            }
            if ( ic.outer )
            {
              if ( jasmin() )
              {
                if ( CHK_OUT_KEYWORD(" outer ") )
                  break;
              }
              else if ( CHK_OUT_STR(" {from}: ") )
              {
                break;
              }
              color_t co = ci;
              if ( co != COLOR_NONE && ic.outer == curClass.This.Name )
                co = COLOR_DNAME;
              if ( OutUtf8(ic.outer, fmt_fullname, co) )
                break;
            }
            if ( !jasmin() )
              out_tagoff(COLOR_AUTOCMT);
            if ( change_line() )
              break;
          }
          while ( i < j );
          if ( curClass.FieldCnt )
            MakeNull();
        }
        goto STOP_NOW;
      } // first entry (zero offset)

      if ( ClassNode.supval(ip, &curField, sizeof(curField)) != sizeof(curField) )
        goto BADIDB;
      curpos = 2;
      if ( !jasmin() && curField.id.utsign )
      {
        if ( sign_out(curField.id.utsign, 0) )
          goto STOP_NOW;
        curpos = 2;
      }
      if ( OutModes(OA_FIELD) )
        goto STOP_NOW;
      if ( !jasmin() && out_field_type() )
        goto STOP_NOW;
      if ( out_index(curField.id.name, QS(fmt_name), COLOR_DNAME, curField.id.extflg & EFL_NAME) )
        goto STOP_NOW;
      if ( chkOutSpace() )
        goto STOP_NOW;
      if ( jasmin() && out_field_type() )
        goto STOP_NOW;

      if ( curField.valNode )
      {
        netnode vnode(curField.valNode);

        uint valcnt = (uint32)vnode.altval(0);
        if ( valcnt == 0 )
          goto BADIDB;
        x.n = 0;
        x.flags = OF_SHOW;
        x.type = o_imm;

        if ( chkOutSymSpace('=') )
          goto STOP_NOW;
        for ( uint i = 1; ; i++)
        {
          uchar flen;

          const_desc_t co;
          if ( vnode.supval(i, &co, sizeof(co)) != sizeof(co) )
          {
            ip = netnode(curField.valNode).altval(i);
            if ( ushort(ip) != 0xFFFF )
              goto BADIDB;
            if ( putShort(ushort(ip >> 16)) )
              goto STOP_NOW;
          }
          else switch ( co.type )
          {
            case CONSTANT_Long:
              x.dtyp = dt_qword;
              goto two_w;
            case CONSTANT_Double:
              x.dtyp = dt_double;
two_w:
              copy_const_to_opnd(x, co);
              flen = 3;
              goto chk_flt;
            case CONSTANT_Float:
              x.dtyp = dt_float;
              x.value = co.value;
              flen = 1;
chk_flt:
              check_float_const(ea, &x.value, flen);
              goto one_w;
            case CONSTANT_Integer:
              x.dtyp = dt_dword;
              x.value = co.value;
one_w:
              if ( !putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
                goto STOP_NOW;
              break;

            case CONSTANT_String:
              if ( !checkLine(2) )
                goto STOP_NOW;
              if ( OutUtf8(co._name, fmt_string, COLOR_STRING) )
                goto STOP_NOW;
              break;

            default:
              UNCOMPAT("out::data");
              break;
          }

          if ( i >= valcnt )
            break;
          if ( chkOutSymSpace(',') )
            goto STOP_NOW;
        } // for(...) (value)
      } // if ( valNode )
      gl_xref = gl_comm = 1;
      if ( !change_line(curpos != 0) )
      {
        uchar addonce = 0;

        if ( jasmin() )
        {
          if ( curField.id.utsign )
          {
            curpos = 4;
            if ( sign_out(curField.id.utsign, -1) )
              goto STOP_NOW;
            addonce = 1;
          }
          if ( curField.id.extflg & XFL_DEPRECATED )
          {
            if ( out_deprecated(4) )
              goto STOP_NOW;
            addonce = 1;
          }
        }

        if ( curField.genNode | curField.annNodes[0] | curField.annNodes[1] )
        {
          addonce = 1;
          if ( !jasmin() )
            block_begin(2);
        }

        if ( curField.genNode && out_includes(curField.genNode, 4) )
          goto STOP_NOW;

        if ( curField.annNodes[0] | curField.annNodes[1] )
        {
          curpos = 4; // prompted output (prefer to new syntax)
          if ( annotation_loop(curField.annNodes, qnumber(curField.annNodes)) )
            goto STOP_NOW;
        }
        if ( addonce )
          block_close(2, "field");
      }
      goto STOP_NOW;
  }

  gl_xref = gl_comm = 1;
  out_zero();
  change_line(curpos != 0);
STOP_NOW:
  term_prompted_output();
  return;

BADIDB:
  DESTROYED("out::data");
}

