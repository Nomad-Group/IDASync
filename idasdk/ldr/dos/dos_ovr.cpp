/*
 *  This Loader Module is written by Ilfak Guilfanov and
 *                        rewriten by Yury Haron
 *
 */
/*
  L O A D E R  pard of MS-DOS file format's (overlayed EXE)
*/

#include "../idaldr.h"
#include  <struct.hpp>
#include <exehdr.h>
#include "dos_ovr.h"

static const char *const stub_class    = "STUBSEG";
static const char *const stub_name_fmt = "stub%03d";
static const char *const ovr_class     = "OVERLAY";
static const char *const ovr_name_fmt  = "ovr%03d";

static uint32 ovr_off = 0;

//------------------------------------------------------------------------
o_type PrepareOverlayType(linput_t *li, exehdr *E)
{
  uint32 flen = qlsize(li);
  uint32 base = E->HdrSize * 16;
  uint32 loadend = base + E->CalcEXE_Length();
  uint32 fbovoff;
  fbov_t fbov;

  ovr_off = 0;

  for ( fbovoff = (loadend + 0xF) & ~0xF; ; fbovoff += 0x10 )
  {
    if ( pos_read(li, fbovoff, &fbov, sizeof(fbov)) )
      break;
    if ( fbov.fb != FB_MAGIC )
      break;
    if ( fbov.ov == OV_MAGIC )
    {
      ovr_off = fbovoff;
      return (fbov.exeinfo > loadend
           || fbov.ovrsize > (flen - fbovoff)
           || fbov.segnum <= 0)
           ? ovr_pascal
           : ovr_cpp;
    }
  }

  exehdr e1;
  fbovoff = (loadend + 511) & ~511;
  flen -= fbovoff;
  if ( !pos_read(li, fbovoff, &e1, sizeof(e1))
    && e1.exe_ident == EXE_ID  //only MZ !
    && flen >= (base = e1.HdrSize*16)
    && e1.TablOff + (e1.ReloCnt*4) <= (flen -= base)
    && e1.CalcEXE_Length() <= flen )
  {
    ovr_off = fbovoff;
    return ovr_ms;
  }
  return ovr_noexe;
}

//------------------------------------------------------------------------
static bool isStubPascal(ea_t ea)
{
  return get_word(ea) == 0x3FCD            // int 3F
      && (int32)get_long(ea+4) > 0         // fileoff
      && get_word(ea+8) != 0               // codesize
      && (short)get_word(ea+10) >= 0       // relsize (assume max 32k)
      && (short)get_word(ea+12) > 0        // nentries
      && (short)get_word(ea+12) < (0x7FFF / sizeof(ovrentry_t)) // nentries
      && isEnabled(toEA(inf.baseaddr + get_word(ea+14), 0)); // prevstub
}

//------------------------------------------------------------------------
linput_t *CheckExternOverlays(void)
{
  char buf[MAXSTR];
  const char *p;
  if ( get_input_file_path(buf, sizeof(buf)) <= 0
    || (p=strrchr(buf, '.')) == NULL
    || stricmp(++p, e_exe) != 0 )
  {
    return NULL;
  }

  for ( segment_t *s = get_first_seg(); s != NULL; s = get_next_seg(s->startEA) )
  {
    ea_t ea = s->startEA;
    if ( isStubPascal(ea) )
    {
      switch ( askyn_c(ASKBTN_NO,
                       "This file contains reference to Pascal-stype overlays\n"
                       "\3Do you want to load it?") )
      {

        case ASKBTN_NO:
          return(NULL);
        case ASKBTN_CANCEL:
          loader_failure();
        default:  //Yes
          break;
      }
      while ( true )
      {
        p = askfile_c(0,
                      set_file_ext(buf, sizeof(buf), buf, "ovr"),
                      "Please enter pascal overlays file");
        CheckCtrlBrk();
        if ( p == NULL )
          return NULL;

        linput_t *li = open_linput(p, false);
        if ( li != NULL )
          return li;
        warning("Pascal style overlays file '%s' is not found", p);
      }
    }
  }
  return NULL;
}

//------------------------------------------------------------------------
static void removeBytes(void)
{
  ea_t ea = inf.ominEA;

  msg("Deleting bytes which do not belong to any segment...\n");
  for ( int i = 0; ; ++i )
  {
    if ( ea >= inf.omaxEA )
      break;

    segment_t *sptr = getnseg(i);

    if ( ea < sptr->startEA )
    {
      showAddr(ea);
      deb(IDA_DEBUG_LDR,
          "Deleting bytes at %a..%a (they do not belong to any segment)...\n",
          ea,
          sptr->startEA);
      if ( disable_flags(ea,sptr->startEA) )
      {
        warning("Maximal number of segments is reached, some bytes are out of segments");
        return;
      }
      CheckCtrlBrk();
    }
    ea = sptr->endEA;
  }
}

//------------------------------------------------------------------------
static int add_struc_fld(
        struc_t *st,
        flags_t flag,
        size_t sz,
        const char *name,
        const char *cmt)
{
  int i = add_struc_member(st, name, BADADDR, flag, NULL, sz);
  if ( i == 0 && cmt != NULL )
    set_member_cmt(get_member_by_name(st, name), cmt, false);
  return i;
}

//------------------------------------------------------
static tid_t member_id(const struc_t *sptr, asize_t offset)
{
  member_t *mptr = get_member(sptr, offset);
  return mptr != NULL ? mptr->id : BADADDR;
}

//------------------------------------------------------
static void describeStub(ea_t stubEA)
{
  static const char stubSname[] = "_stub_descr";
  static tid_t id = 0;

  if ( id == 0
    && (id=get_struc_id(stubSname)) == BADNODE )
  {
    struc_t *st = get_struc(add_struc(BADADDR, stubSname));
    if ( st == NULL )
      goto badst;
    st->props |= SF_NOLIST;
    if ( add_struc_fld(st, byteflag()|hexflag(), 2,
                       "int_code", "Overlay manager interrupt")
      || add_struc_fld(st, wordflag()|hexflag(), sizeof(short),
                       "memswap", "Runtime memory swap address")
      || add_struc_fld(st, dwrdflag()|hexflag(), sizeof(int32),
                       "fileoff", "Offset in the file to the code")
      || add_struc_fld(st, wordflag()|hexflag(), sizeof(short),
                       "codesize", "Code size")
      || add_struc_fld(st, wordflag()|hexflag(), sizeof(short),
                       "relsize", "Relocation area size")
      || add_struc_fld(st, wordflag()|decflag(), sizeof(short),
                       "nentries", "Number of overlay entries")
      || add_struc_fld(st, wordflag()|segflag(), sizeof(short),
                       "prevstub", "Previous stub")
      || add_struc_fld(st, byteflag()|hexflag(), STUBUNK_SIZE,
                       "workarea", NULL) )
    {
badst:
      warning("Failed to create stub structure descriptor");
      id = BADNODE;
    }
    else
    {
      array_parameters_t apt;
      apt.flags = AP_ALLOWDUPS;
      apt.lineitems = 8;
      apt.alignment = -1; // nonalign
      set_array_parameters(member_id(st, 0), &apt);
      set_array_parameters(member_id(st,offsetof(stub_t,unknown)), &apt);
      // st->props |= SF_NOLIST;
      // save_struc(st);
      id = st->id;
    }
  }

  ushort tmp = get_word(stubEA + offsetof(stub_t, prevstub));
  if ( tmp != 0 )
    put_word(stubEA + offsetof(stub_t, prevstub), uint16(tmp + inf.baseaddr));

  tmp = get_word(stubEA + offsetof(stub_t, nentries));

  if ( id != BADNODE )
  {
    do_unknown_range(stubEA, sizeof(stub_t), DOUNK_EXPAND);
    doStruct(stubEA, sizeof(stub_t), id);
  }

  stubEA += sizeof(stub_t);

  if ( tmp != 0 )
  {
    do
    {
      auto_make_proc(stubEA);
      stubEA += 5;
      CheckCtrlBrk();
    } while ( --tmp );
  }
}

//------------------------------------------------------------------------
static void load_overlay(
        linput_t *li,
        uint32 exeinfo,
        ea_t stubEA,
        segment_t *s,
        int32 fboff)
{
  ea_t entEA = stubEA + sizeof(stub_t);
  stub_t stub;

  if ( !get_many_bytes(stubEA, &stub, sizeof(stub)) )
    errstruct();
  msg("Overlay stub at %a, code at %a...\n", stubEA, s->startEA);
  if ( stub.CDh != 0xCD )
    errstruct();   // bad stub

  //i now load overlay code:
  bool waszero = false;
  if ( !stub.codesize ) // IDA  doesn't allow 0 length segments
  {
    ++stub.codesize;
    waszero = true;
  }
  s->endEA = s->startEA + stub.codesize;
  file2base(li, fboff+stub.fileoff, s->startEA, s->endEA,
            fboff == 0
          ? FILEREG_NOTPATCHABLE
          : FILEREG_PATCHABLE);
  if ( waszero )
  {
    s->type = SEG_NULL;
    stub.codesize = 0;
  }

  uint i;
  for( i = 0; i < stub.nentries; ++i )
  {
    showAddr(entEA);
    put_byte(entEA, 0xEA);     // jmp far
    ushort offset = get_word(entEA+2);
    put_word(entEA+1, offset); // offset
    put_word(entEA+3, s->sel); // selector
    auto_make_proc(toEA(ask_selector(s->sel), offset));
    entEA += sizeof(ovrentry_t);
    CheckCtrlBrk();
  }

  qlseek(li, fboff + stub.fileoff + stub.codesize);

  fixup_data_t fd;
  fd.type = FIXUP_SEG16;
  fd.off  = 0;
  fd.displacement = 0;

  uint relcnt = stub.relsize / 2;
  validate_array_count(li, &relcnt, sizeof(ushort), "Relocation count");
  if ( relcnt != 0 )
  {
    ushort *relb = qalloc_array<ushort>(relcnt);
    if ( !relb )
      nomem("overlay relocation table");

    lread(li, relb, sizeof(ushort)*relcnt);
    int32 pos = qltell(li); //must??

    ushort *relc = relb;
    do
    {
      if ( *relc > stub.codesize )
        errstruct();

      ea_t xEA = s->startEA + *relc++;
      showAddr(xEA);
      ushort relseg = get_word(xEA);
      if ( exeinfo != 0 )
      {
        seginfo_t si;

        if ( pos_read(li, exeinfo + relseg, &si, sizeof(si)) )
          errstruct();
        relseg = si.seg;
      }

      fd.sel = relseg + (ushort)inf.baseaddr;
      set_fixup(xEA, &fd);
      put_word(xEA, fd.sel);
      CheckCtrlBrk();
    } while ( --relcnt );
    qfree(relb);
    qlseek(li, pos);
  }
}

//------------------------------------------------------------------------
static void add_seg16(ea_t ea)
{
  segment_t s;
  s.sel     = ea >> 4;
  s.startEA = ea;
  s.endEA   = BADADDR;
  s.align   = saRelByte;
  s.comb    = scPub;
  add_segm_ex(&s, NULL, NULL, ADDSEG_NOSREG);
}

//------------------------------------------------------------------------
static sel_t AdjustStub(ea_t ea) // returns prev stub
{
  segment_t *seg = getseg(ea);

  if ( ea != seg->startEA )
    add_seg16(ea);

  ushort nentries = get_word(ea+12);
  uint32 segsize = sizeof(stub_t) + nentries * sizeof(ovrentry_t);
  seg = getseg(ea);

  asize_t realsize = seg->endEA - seg->startEA;
  if ( segsize > realsize )
    return BADSEL;      // this stub is bad

  if ( segsize != realsize )
  {
    ea_t next = seg->startEA + segsize;

    set_segm_end(seg->startEA, next, 0);
    next += 0xF;
    next &= ~0xF;
    if ( isEnabled(next) )
    {
      segment_t *s = getseg(next);
      if ( s == NULL )
        add_seg16(next);
    }
  }
  return get_word(ea + 14);
}

//------------------------------------------------------------------------
void LoadPascalOverlays(linput_t *li)
{
  //AdjustPascalOverlay
  for ( ea_t ea = inf.minEA; ea < inf.maxEA; )
  {
    ea &= ~0xF;
    if ( isStubPascal(ea) )
    {
      AdjustStub(ea);
      ea = getseg(ea)->endEA;
      ea += 0xF;
      CheckCtrlBrk();
    }
    else
    {
      ea += 0x10;
    }
  }
  //-
  ea_t ea;
  int i = 0;
  for ( segment_t *s0 = get_first_seg(); s0 != NULL; s0 = get_next_seg(ea), ++i )
  {
    ea = s0->startEA;

    if ( get_byte(ea) != 0xCD || get_byte(ea+1) != 0x3F )
      continue;
    set_segm_class(s0, stub_class);
    set_segm_name(s0, stub_name_fmt, i);

    segment_t s;
    s.align   = saRelByte;
    s.comb    = scPub;
    s.align   = saRelPara;
    s.startEA = (inf.maxEA + 0xF) & ~0xF;
    s.sel = setup_selector(s.startEA >> 4);
    // 04.06.99 ig: what is exeinfo and why it is passed as 0 here?
    load_overlay(li, 0/*???*/, ea, &s, ovr_off); //i
    if ( !add_segm_ex(&s, NULL, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();
    set_segm_name(&s, ovr_name_fmt, i);
    describeStub(ea);
    CheckCtrlBrk();
  }
  removeBytes();
}

//------------------------------------------------------------------------
static ea_t CppInfoBase(fbov_t *fbov)
{
  seginfo_t si;
  ea_t siEA = get_fileregion_ea(fbov->exeinfo);

  if ( siEA == BADADDR
    || !get_many_bytes(siEA, &si, sizeof(si)) )
  {
    errstruct();
  }

  if ( (si.flags & SI_OVR) && si.seg ) //possible truncation
  {
    ushort lseg = si.seg;

    msg("Probbly the input file was truncated by 'unp -h'. Searching the base...\n");
    do
    {
      if ( si.seg > lseg )
        errstruct();
      lseg = si.seg;

      if ( siEA < inf.ominEA+sizeof(si)
        || !get_many_bytes(siEA -= sizeof(si), &si, sizeof(si)) )
      {
        errstruct();
      }
      fbov->exeinfo -= sizeof(si);
      CheckCtrlBrk();
    } while ( si.seg );
    add_pgm_cmt("Real (before unp -h) EXEinfo=%08X", fbov->exeinfo);
  }
  return siEA;
}

//------------------------------------------------------------------------
sel_t LoadCppOverlays(linput_t *li)
{
  fbov_t fbov;
  sel_t  dseg = BADSEL;

  if ( pos_read(li, ovr_off, &fbov, sizeof(fbov)) )
    errstruct();
  add_pgm_cmt("Overlays: base=%08X, size=%08X, EXEinfo=%08X",
              ovr_off, fbov.ovrsize, fbov.exeinfo);
  ovr_off += sizeof(fbov_t);

  if ( fbov.segnum == 0 )
    errstruct();

  ea_t    siEA = CppInfoBase(&fbov);
  ushort  lseg = 0;
  for ( int32 i = 0; i < fbov.segnum; ++i )
  {
    seginfo_t si;

    if ( !get_many_bytes(siEA, &si, sizeof(si)) )
      errstruct();
    siEA += sizeof(si);

    if ( si.maxoff == 0xFFFF )
      continue;  // skip EXEINFO & OVRDATA
    if ( si.maxoff <= si.minoff )
      continue;
    if ( si.seg < lseg )
      errstruct( );
    lseg = si.seg;

    si.seg += (ushort)inf.baseaddr;

    const char *sclass = NULL;
    segment_t s;      //i initialize segment_t with 0s
    s.align  = saRelByte;
    s.comb   = scPub;
    if ( si.seg == inf.start_ss )
    {
      sclass = CLASS_STACK;
      s.type = SEG_DATA;
      s.comb = scStack;
    }
    if ( si.flags & SI_COD )
    {
      sclass = CLASS_CODE;
      s.type = SEG_CODE;
    }
    if ( si.flags & SI_DAT )
    {
      sclass = CLASS_BSS;
      s.type = SEG_DATA;
      dseg   = si.seg;
    }
    s.name = 0;
    if ( si.flags & SI_OVR )
    {
      s.align = saRelPara;
      s.startEA = (inf.maxEA + 0xF) & ~0xF;
      s.sel = setup_selector(s.startEA >> 4);
      //i endEA is set in load_overlay()
      load_overlay(li, fbov.exeinfo, toEA(si.seg, 0), &s, ovr_off);
      if ( s.type != SEG_NULL )
        s.type = SEG_CODE;
      if ( !add_segm_ex(&s, NULL, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
        loader_failure();
      set_segm_name(&s, ovr_name_fmt, i);
      s.name = 0;
      s.type = SEG_NORM;        // undefined segment type
      sclass = stub_class;
    }
    s.sel     = si.seg;
    s.startEA = toEA(s.sel, si.minoff);
    s.endEA   = toEA(s.sel, si.maxoff);
    if ( !add_segm_ex(&s, NULL, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();
    if ( si.flags & SI_OVR )
    {
      describeStub(s.startEA);
      set_segm_name(&s, stub_name_fmt, i);
    }
    CheckCtrlBrk();
  }
  removeBytes();
  return dseg;
}

//------------------------------------------------------------------------
//+
//------------------------------------------------------------------------
static netnode msnode;

struct modsc_t
{
  uint32 bpos;
  uint32 size;
  ushort Toff;
  ushort Hsiz;
  ushort Rcnt;
  ushort Mpara;
};

static ea_t ref_off_EA;
static ea_t ref_ind_EA;
static uint ref_oi_cnt;

//------------------------------------------------------------------------
static uint CreateMsOverlaysTable(linput_t *li, bool *PossibleDynamic)
{
  modsc_t o;
  uint    Count = 0;
  uint32  flen = qlsize(li);

  o.bpos = ovr_off;
  msnode.create();
  msg("Searching for the overlays in the file...\n");
  while ( o.bpos + sizeof(exehdr) < flen )
  {
    exehdr  E;
    uint32  delta;

    if ( pos_read(li, o.bpos, &E, sizeof(E)) )
      errstruct();

    o.size = E.CalcEXE_Length();
    delta = (uint32)(o.Hsiz = E.HdrSize) * 16;
    o.Toff = E.TablOff;
    o.Rcnt = E.ReloCnt;
    o.Mpara = (ushort)((o.size + 0xF) >> 4);

    uint32 ost = flen - o.bpos;
    if ( E.exe_ident != EXE_ID   //only MZ !
      || ost < delta
      || (uint32)o.Toff + (E.ReloCnt*4) > (ost -= delta)
      || o.size > ost)
    {
      return Count;
    }
    CheckCtrlBrk();

    msnode.supset(++Count, &o, sizeof(o));
    ovr_off = o.bpos + delta + o.size;
    uint32 d2 = align_up(ovr_off, 512);
    if ( o.bpos == d2 )
    {
      warning("Too small overflay size %u, stopped processing them", delta+o.size);
      break;
    }
    o.bpos = d2;
    if ( E.Overlay != Count )
      *PossibleDynamic = false;
  }
  ovr_off = 0;
  return Count;
}

//------------------------------------------------------------------------
static void LoadMsOvrData(linput_t *li, uint Count, bool Dynamic)
{
  fixup_data_t fd;

  fd.type         = FIXUP_SEG16;
  fd.off          = 0;
  fd.displacement = 0;

  for ( uint i = 1; i <= Count; ++i )
  {
    modsc_t o;

    // skip dropped overlays
    if ( msnode.supval(i, &o, sizeof(o)) != sizeof(o) )
      continue;

    segment_t s;
    s.comb    = scPub;
    s.align   = saRelPara;
    s.startEA = (inf.maxEA + 0xF) & ~0xF;
    s.sel = setup_selector(s.startEA >> 4);
    msnode.altset(i, s.sel);
    s.endEA = s.startEA + ((uint32)o.Mpara << 4);
    file2base(li,
              o.bpos + o.Hsiz*16,
              s.startEA,
              s.startEA + o.size,
              FILEREG_PATCHABLE);
    if ( !add_segm_ex(&s, NULL, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();
    set_segm_name(&s, ovr_name_fmt, i);

    qlseek(li, o.bpos + o.Toff);

    for ( uint j = o.Rcnt; j; --j )
    {
      ushort buf[2];

      lread(li, buf, sizeof(buf));

//ATTENTION!!! if Dynamic (ms-autopositioning) segment part of relocation
//             address == pseudodata segment  to load (from data in ovr!)
//             We should checked it but don't have any testcase
      ea_t xEA = Dynamic
               ? s.startEA + buf[0]
               : s.startEA + toEA(buf[1], buf[0]);

      if ( xEA >= s.endEA )
        errstruct();

      showAddr(xEA);

      ushort ubs = ushort(get_word(xEA) + inf.baseaddr);
      put_word(xEA, ubs);
      fd.sel = ubs;
      set_fixup(xEA, &fd);
      add_segm_by_selector(ubs, CLASS_CODE);
      CheckCtrlBrk();
    }
  }
}

//------------------------------------------------------------------------
static sel_t SearchMsOvrTable(uint *Cnt)
{
  modsc_t dsc;
  if ( msnode.supval(1, &dsc, sizeof(dsc)) != sizeof(dsc) )
  {
interr:
    error("Internal error");
  }

  uint32 src[2] = { 0, dsc.bpos };
  ea_t dstea, sea, ea = inf.minEA;
  uint AddSkip, Count = *Cnt;
  uint i, j;  // watcom ...
  segment_t *s;

  msg("Searching the overlay reference data table...\n");
  while ( ea + sizeof(src) < inf.maxEA
       && (sea = bin_search(ea,
                            inf.maxEA,
                            (uchar *)src,
                            NULL,
                            sizeof(src),
                            BIN_SEARCH_FORWARD,
                            BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK)) != BADADDR )
  {
    ea = sea + sizeof(uint32);
    s = getseg(ea);
    if ( s == NULL
      || ea - s->startEA < sizeof(uint32)*(Count+1)
      || ea + (2*sizeof(uint32) * Count) > s->endEA )
    {
nextfndadd:
      ea += sizeof(uint32);
nextfnd:
      continue;
    }

    AddSkip = 0;
    for ( i = 2; i <= Count + AddSkip; ++i )
    {
      ea += sizeof(uint32);
      uint32 pos = get_long(ea);

      if ( pos == 0 )
      {
        ++AddSkip;
        if ( ea + (2*sizeof(uint32) * (Count+AddSkip-i)) > s->endEA )
          goto nextfnd;
      }
      else
      {
        if ( msnode.supval(i - AddSkip, &dsc, sizeof(dsc)) != sizeof(dsc) )
          goto interr;
        if ( pos != dsc.bpos )
          goto nextfndadd;
      }
    }
    goto found;
  }
badtable:
  ref_oi_cnt = (uint)-1;
  return BADSEL;

found:
  if ( AddSkip )
  {
    ea = sea + sizeof(uint32);
    for ( i = 2; i <= Count; ++i )
    {
      if ( !get_long(ea += sizeof(uint32)) )
      {
        if ( !AddSkip )
          goto interr;
        --AddSkip;
        for ( j = Count; j >= i; --j )
        {
          if ( msnode.supval(j, &dsc, sizeof(dsc)) != sizeof(dsc) )
            goto interr;
          msnode.supset(j+1, &dsc, sizeof(dsc));
        }
        msnode.supdel(i);
        ++Count;
        CheckCtrlBrk();
      }
    }
    if ( AddSkip )
      goto interr;
  }

  //msg("Found disk blocks table\n");
  ea = sea - ((Count-1) * sizeof(ushort)) - 1;  // -1 -- unification
  do
  {
    ea = bin_search(s->startEA,
                    ea+1,
                    (uchar *)src,
                    NULL,
                    sizeof(ushort),
                    BIN_SEARCH_BACKWARD,
                    BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK);
    if ( ea == BADADDR)
      goto badtable;
  } while ( (sea - ea) % sizeof(ushort) );

  ref_oi_cnt = (sea - ea) / sizeof(ushort);
  if ( ref_oi_cnt <= 1 )
    goto badtable;
  ref_ind_EA = ea;

  //msg("Check all tables...\n");
  j = Count;
  while ( (ea += sizeof(ushort)) < sea )
  {
    i = get_word(ea);
    if ( i > j )
    {
      if ( j == *Cnt )
        goto badtable;
      j = i;
    }
  }
  if ( (i = j - Count) != 0 )
  {
    AddSkip = i;
    do
    {
      if ( get_long(sea - sizeof(uint32)) )
        break;
      if ( (ref_oi_cnt -= 2) <= 1 )
        goto badtable;
      sea -= sizeof(uint32);
    } while ( --i );
    AddSkip -= i;
    for ( j = Count; j; --j )
    {
      if ( msnode.supval(j, &dsc, sizeof(dsc)) != sizeof(dsc) )
        msnode.supdel(j + AddSkip);
      else
        msnode.supset(j + AddSkip, &dsc, sizeof(dsc));
    }
    do
    {
      msnode.supdel(++j);
    }
    while ( j < AddSkip );
    Count += AddSkip;
    CheckCtrlBrk();
    if ( i )
    {
      ea = sea + Count*sizeof(uint32);
      Count += i;
      do
      {
        if ( get_long(ea += sizeof(uint32)) )
          goto badtable;
      }
      while ( --i );
    }
  }

  dstea = sea;

  ea = ref_ind_EA - (ref_oi_cnt*sizeof(ushort));
  if ( get_prev_fixup_ea(ea+1) != ea )
    ask_for_feedback("Absent relocation at start of offset table");

  ref_off_EA = ea;

  sea = ref_ind_EA;
  for ( i = 1; i < ref_oi_cnt; ++i )
  {
    ea  += sizeof(ushort);
    sea += sizeof(ushort);

    uint rsz = get_word(ea);

    if ( msnode.supval(get_word(sea), &dsc, sizeof(dsc)) != sizeof(dsc) )
    {
      if ( rsz )
        goto badofftb;
      msg("An overlay index %u in the table of indexes points to a missing overlay\n", i);
    }
    else if ( rsz >= dsc.size )
    {
badofftb:
      ask_for_feedback("Incompatible offset table");
    }
  }

  sea = dstea + (Count+1)*sizeof(uint32);
  for ( i = 1; i <= Count; ++i )
  {
    sea += sizeof(uint32);
    uint32 dt = get_long(sea);

    if ( msnode.supval(i, &dsc, sizeof(dsc)) != sizeof(dsc) )
    {
      if ( dt )
      {
badmemtb:
        ask_for_feedback("Incompatible mem-size table");
      }
      continue;
    }

    if ( !dt )
    {
      ask_for_feedback("Zero overlay memory size in description table");
      goto badtable;
    }

    if ( dt < dsc.Mpara || dt >= 0x1000 )
      goto badmemtb;

    //Possiblee needed for segment with unitialized data at top, but not sampled...
    if ( dt > dsc.Mpara )
    {
      dsc.Mpara = (ushort)dt;
      msnode.supset(i, &dsc, sizeof(dsc));
    }
  }

  msg("All tables OK\n");
  doWord(ref_off_EA, i = ref_oi_cnt*sizeof(ushort));
  do_name_anyway(ref_off_EA, "ovr_off_tbl");
  doWord(ref_ind_EA, i);
  do_name_anyway(ref_ind_EA, "ovr_index_tbl");
  *Cnt = Count;
  i = (Count + 1) * sizeof(uint32);
  doDwrd(dstea, i);
  do_name_anyway(dstea, "ovr_start_tbl");
  dstea += i;
  doDwrd(dstea, i);
  do_name_anyway(dstea, "ovr_memsiz_tbl");
  return s->sel;
}

//------------------------------------------------------------------------
static segment_t *MsOvrStubSeg(uint *stub_cnt, ea_t r_top, sel_t dseg)
{
  msg("Searching for the stub segment...\n");
  for ( int i = 0; i < segs.get_area_qty(); ++i )
  {
    segment_t *seg = getnseg(i);
    if ( seg->sel == dseg )
      continue;
    ea_t ea = seg->startEA;
    uchar buf[3*sizeof(ushort)];

    if ( ea >= r_top )
      break;

    if ( !get_many_bytes(ea, buf, sizeof(buf)) )
      continue;
    if ( *(uint32 *)buf || *(ushort *)&buf[sizeof(uint32)] )
      continue;

    uint  cnt = 0;
    uchar frs = (uchar)-1;
    while ( (ea += sizeof(buf)) < seg->endEA - sizeof(buf) )
    {
      if ( (frs = get_byte(ea)) != 0xCD || get_byte(ea+1) != 0x3F )
        break;
      ushort ind = get_word(ea + sizeof(ushort));
      if ( !ind || ind > ref_oi_cnt )
        break;
      ++cnt;
      CheckCtrlBrk();
    }
    if ( !frs && cnt >= ref_oi_cnt )
    {
      *stub_cnt = cnt;
      return seg;
    }
  }
  return NULL;
}

//------------------------------------------------------------------------
static void CreateMsStubProc(segment_t *s, uint stub_cnt)
{
  ea_t ea = s->startEA;

  set_segm_name(s, "STUB");
  set_segm_class(s, CLASS_CODE);
  doByte(ea, 3*sizeof(ushort));
  ea += 3*sizeof(ushort);
  msg("Patching the overlay stub-segment...\n");
  for ( uint ind, i = 0; i < stub_cnt; ++i, ea += 3*sizeof(ushort) )
  {
    ind = get_word(ea+2);
    if ( ind != 0 )
    {
      if ( ind >= ref_oi_cnt )
      {
badref:
        ask_for_feedback("Illegal reference in overlay call interrupt");
        continue;
      }

      ind *= sizeof(ushort);
      uint off = (uint)get_word(ea+4) + get_word(ref_off_EA + ind);
      ind = get_word(ref_ind_EA + ind); // overlay number
      ushort sel = (ushort)msnode.altval(ind);
      modsc_t o;
      if ( msnode.supval(ind, &o, sizeof(o)) != sizeof(o) )
        goto badref;
      if ( off >= o.size )
        goto badref;

      showAddr(ea);
      put_byte(ea, 0xEA);   // jmp far
      put_word(ea+1, off);  // offset
      put_word(ea+3, sel);  // selector
      put_byte(ea+5, 0x90); //NOP -> for autoanalisis
      auto_make_proc(ea);
      auto_make_proc(toEA(ask_selector(sel), off));
      CheckCtrlBrk();
    }
  }
  doAlign(ea, s->endEA - ea, 0);
}

//------------------------------------------------------------------------
sel_t LoadMsOverlays(linput_t *li, bool PossibleDynamic)
{
  sel_t dseg = BADSEL;
  uint Cnt = CreateMsOverlaysTable(li, &PossibleDynamic);

  if ( ovr_off )
    warning("File has extra information\n"
            "\3Loading 0x%X bytes, total file size 0x%X",
            ovr_off, qlsize(li));

  if ( Cnt )
  {
    dseg = SearchMsOvrTable(&Cnt);
    if ( dseg != BADSEL )
      PossibleDynamic = false;
    else if ( !PossibleDynamic )
      ask_for_feedback("Can not find the overlay call data table");

    ea_t r_top = inf.maxEA;
    LoadMsOvrData(li, Cnt, PossibleDynamic);

    if ( ref_oi_cnt != (uint)-1 )
    {
      uint stub_cnt;
      segment_t *s = MsOvrStubSeg(&stub_cnt, r_top, dseg);

      if ( s != NULL )
        CreateMsStubProc(s, stub_cnt);
      else
        ask_for_feedback("The overlay-manager segment not found");
    }
  }
  msnode.kill();
  return dseg;
}
