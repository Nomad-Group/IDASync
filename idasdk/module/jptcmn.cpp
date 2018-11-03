// common file to handle jump tables

#include <limits.h>

//#define JUMP_DEBUG
//----------------------------------------------------------------------
enum jump_table_type_t
{
  JT_NONE,        // No jump table
  JT_FLAT32,      // Flat 32-bit jump table
  JT_ARM_LDRB,    // pc + byte(table[i])  (possibly << 1)
  JT_ARM_LDRH,    // pc + word(table[i])  (possibly << 1)
  JT_LAST,
};

// Class to check for a jump table sequence.
// This class should be used in preference to the hard encoding of jump table sequences
// because it allows for:
//      - instruction rescheduling
//      - intermingling the jump sequence with other instructions
//      - sequence variants
//
// For this class:
//   all instructions of the sequence are numbered starting from the last instruction.
//   The last instruction has the number 0.
//   The instruction before the last instruciton has the number 1, etc.
//   There is a virtual function jpiN() for each instruction of the sequence
//   These functions return true if 'insn' is filled with the required instruction
//
// The comparison is made in the match() function:
//
//   ea points to the last instruction of the sequence (instruction #0)
//
//   the 'depends' array contains dependencies between the instructions of the sequence.
//   For example:
//      ARM thumb LDRH switch
//      7 SUB     Ra, #minv (optional)
//      6 CMP     Ra, #size
//      5 BCS     defea
//      4 ADR     Rb, jt
//      3 ADD     Rb, Rb, Ra
//      2 LDRH    Rb, [Rb,Ra]
//      1 LSL     Rb, Rb, #1
//      0 ADD     PC, Rb
//   In this sequence, instruction #0 depends on the value of Rb which is produced
//   by the instruction #1. So, the instruction #0 depends on #1. Therefore, depends[0]
//   will contain '1' as its element.
//   The instruction #2 depends on 3 registers: Ra and Rb, or in other words,
//   it depends on the instructions #4 and #6. Therefore, depends[2] will contain { 4, 6 }
//   Maximum 2 dependencies per instruction are allowed.
//
//   The 'roots' array contains the first instruction of the dependency chains.
//   In our case we can say that there are 2 dependency chains:
//      0 -> 1 -> 2 -> 3 -> 4
//                       -> 6 -> 7
//      5 -> 6 -> 7
//   Therefore the roots array will consist of {1, 5}.
//   0 denotes the end of the chain and can not be the root of a dependency chain
//   Usually 1 is a root of any jump sequence.
//
//   The dependencies array allows to check for optimized sequences of instrucitons.
//   If 2 instructions are not dependent on each other, they may appear in any order.
//   (for example, the instruction #4 and the instruction sequence #5-6-7 may appear
//   in any order because they do not depend on each other)
//   Also any other instructions not modifying the register values may appear between
//   the instructions of the sequence (due to the instruction rescheduling performed
//   by the compiler).
//
//   Provision for optional instructions:
//   The presence of an optional instruction in the sequence (like #7) is signalled
//   by a negative number of the dependency in the 'depends' array.
//
//   Provision for variable instructions:
//   In some cases several variants of the same instructions may be supported.
//   For example, the instruction #5 might be BCS as well as BGE. It is the job of
//   the jpi5() function to check for all variants.
//
//   Provision to skip some instructions of the sequence:
//   Sometimes one variant of the instruction might mean that a previous instruction
//   must be missing. For example, the instructions #5, #6 might look like
//
//       Variant 1   Variant 2   Variant 3
//    6  BCC label
//    5  B defea     BGE defea   BCS defea
//   label:
//
//   Then jpi5() must behave like this:
//      if the instruction in 'insn' is 'BSC' or 'BGE'
//        then skip instruction #6. For this:
//              skip[6] = true;
//      if the instruction in 'insn' is 'B'
//              remember defea; return true;
//   And jpi6() must behave like this:
//      check if the instruction in 'insn' is 'BCC' and jump to the end of instruction #5
//
// In order to use the 'jump_pattern_t' class you should derive another class from it
// and define the jpiN() virtual functions.
// Then you have to define the 'depends' and 'roots' arrays and call the match()
// function.
// If you processor contains instructions who modify registers in peculiar ways
// you might want to override the check_spoiled() function.

//-V:jump_pattern_t:730 not all members of a class are initialized inside the constructor
class jump_pattern_t
{
public:
  typedef bool (jump_pattern_t::*check_insn_t)(void);
  jump_pattern_t(switch_info_t *si, const char *roots, const char (*depends)[2]);

  switch_info_t *si; // answers will be here
  insn_t insn;   // current instruction

  enum { NINS = 16 };   // the maximum length of the sequence
  ea_t eas[NINS];
  bool skip[NINS];
  check_insn_t check[NINS];
  int r[16];
  bool spoiled[16];
  ea_t minea;           // minimal allowed ea for the switch idiom

  const char *roots;            // dependency tree roots
  const char (*depends)[2];     // positive numbers - instruction on which we depend
                                // negative means the dependence is optional,
                                //   the other instruction might be missing
  bool allow_noflows;
  bool allow_farrefs;           // are farrefs allowed?
  bool failed;
  bool farref;                  // used decode_preceding_insn() and got far reference?

  // for fragmented switch idioms, cmp/jbe might be located in a separate
  // fragment. we must not mark these instructions as part of the switch
  // idiom because doing so would spoil the program logic for the decompiler
  // and make the switch operator unreachable. the following vector keeps
  // addresses of all instructions which must not be marked. this vector is
  // maintained by derived classes.
  eavec_t remote_code;

  // this should return true if the current instruction (in "insn")
  // has a delay slot after it.
  virtual bool has_delay_slot(void) { return false; }

  virtual bool handle_mov(void) { return false; }
  virtual void check_spoiled(void);

  // check that insn.ea jumps to addr_to and only it
  // can be used to skip instructions which glue blocks together
  // this function can change current instruction (member 'insn')
  // (e.g. in case of delayed jump, see sh3/emu.cpp)
  virtual bool is_branch_to(ea_t /*addr_to*/) { return false; }
  void spoil(int reg);
  bool follow_tree(ea_t ea, int n);
  int find_reg(int reg); // -1 - not found
  bool is_matched_ea(ea_t ea);
  // mark swith instructions to be ignored by the decompiler
  // by default do not mark the indirect jmp (eas[0]) as ignored
  // it will be used to recognize switch idioms
  virtual void mark_switch_insns(int last = NINS-1, int first = 1);

  virtual bool jpi0(void) = 0;
  virtual bool jpi1(void) { return false; }
  virtual bool jpi2(void) { return false; }
  virtual bool jpi3(void) { return false; }
  virtual bool jpi4(void) { return false; }
  virtual bool jpi5(void) { return false; }
  virtual bool jpi6(void) { return false; }
  virtual bool jpi7(void) { return false; }
  virtual bool jpi8(void) { return false; }
  virtual bool jpi9(void) { return false; }
  virtual bool jpia(void) { return false; }
  virtual bool jpib(void) { return false; }
  virtual bool jpic(void) { return false; }
  virtual bool jpid(void) { return false; }
  virtual bool jpie(void) { return false; }
  virtual bool jpif(void) { return false; }
  virtual bool start_tree(ea_t /*ea*/, int /*n*/) { return true; }

  bool match(const insn_t &insn);

  // remove compiler warnings -- class with virtual functions MUST have virtual destructot
  virtual ~jump_pattern_t() {}

  // helper for mov instruction tracing (see handle_mov() above)
  op_t r_moved[NINS];
  inline bool mov_set(uint16 reg, const op_t &op, bool spoil_reg = true);
  inline bool is_same(const op_t &op, int r_i);
};


//----------------------------------------------------------------------
#ifdef JUMP_DEBUG
inline void jmsg(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}
#else
inline void jmsg(const char *, ...) {}
#endif

//----------------------------------------------------------------------
inline jump_pattern_t::jump_pattern_t(
        switch_info_t *_si,
        const char *_roots,
        const char (*_depends)[2])
  : si(_si),
    roots(_roots),
    depends(_depends),
    allow_noflows(true),
    allow_farrefs(true)
{
//  *size  = INT_MAX;
}

//----------------------------------------------------------------------
int jump_pattern_t::find_reg(int reg)
{
  for ( int i=0; i < qnumber(r); i++ )
    if ( r[i] == reg )
      return i;
  return -1;
}

//----------------------------------------------------------------------
void jump_pattern_t::spoil(int reg)
{
  // same register can be listed under different indexes
  // so check them all
  for ( int i=0; i < qnumber(r); i++ )
  {
    if ( r[i] == reg )
      spoiled[i] = true;
  }
}

//----------------------------------------------------------------------
void jump_pattern_t::check_spoiled(void)
{
  uint32 F = insn.get_canon_feature();
  if ( F != 0 )
  {
    for ( int i=0; i < UA_MAXOP; i++ )
    {
      if ( (F & (CF_CHG1<<i)) == 0 )
        continue;
      const op_t &x = insn.ops[i];
      switch ( x.type )
      {
        case o_reg:
          spoil(x.reg);
          break;
      }
    }
  }
}

//----------------------------------------------------------------------
bool jump_pattern_t::is_matched_ea(ea_t ea)
{
  for ( int i=0; i < qnumber(eas) && eas[i] != BADADDR; i++ )
    if ( eas[i] == ea )
      return true;
  return false;
}

//----------------------------------------------------------------------
bool jump_pattern_t::follow_tree(ea_t ea, int n)
{
  if ( n == 0 )
    return true;
  int rsaved[qnumber(r)];
  op_t msaved[qnumber(r_moved)];
  bool ssaved[qnumber(spoiled)];
  CASSERT(sizeof(rsaved) == sizeof(r));
  CASSERT(sizeof(msaved) == sizeof(r_moved));
  CASSERT(sizeof(spoiled) == sizeof(spoiled));
  memcpy(rsaved, r, sizeof(r));
  memcpy(msaved, r_moved, sizeof(r_moved));
  memcpy(ssaved, spoiled, sizeof(spoiled));
  ea_t saved_ea = ea;
  bool optional = false;
  if ( n < 0 )
  {
    optional = true;
    n = -n;
  }
  jmsg("follow_tree(%a, %d)\n", ea, n);
  bool found_insn = false;
  if ( !skip[n] )
  {
    if ( eas[n] == BADADDR )
    {
      ea_t cur_addr = ea;
      while ( true )
      {
        farref = false;
        bool tried_farref = false;
        ea_t prev = BADADDR;
        if ( (allow_noflows && !allow_farrefs) || is_flow(get_flags(cur_addr)) )
        {
          while ( true )
          {
            prev = decode_prev_insn(&insn, cur_addr);
            // skip all matched addresses
            if ( prev == BADADDR || !is_matched_ea(prev) )
              break;
            if ( !allow_noflows && !is_flow(get_flags(prev)) )
              break;
            cur_addr = prev;
          }
        }
        if ( prev == BADADDR )
        {
          if ( !allow_farrefs )
            break;
FARREF:
          tried_farref = true;
          if ( decode_preceding_insn(&insn, cur_addr, &farref) == BADADDR )
            break;

          // handle delay slot if this instruction has one
          if ( farref && has_delay_slot() )
          {
            if ( decode_insn(&insn, insn.ea+insn.size) > 0 )
            {
              jmsg("%a: handling delay slot instruction\n", insn.ea);
              cur_addr = insn.ea;
              farref = false;
            }
          }

          // skip branches which are used to glue blocks together
          if ( farref && is_branch_to(cur_addr) )
          {
            if ( is_call_insn(insn) )
            {
              jmsg("%a: detected call, failed\n", insn.ea);
              break; // do not continue to other functions
            }
            cur_addr = insn.ea;
            continue;
          }
        }
        ea_t farref_to_try = cur_addr;
        cur_addr = insn.ea;
        if ( cur_addr < minea )
        {
          // if we crossed 'minea' because we switched
          // to another chunk of the same function,
          // update it accordingly
          func_t *pfn = get_fchunk(minea);
          if ( pfn != NULL && pfn->start_ea == minea )
          {
            pfn = get_func(cur_addr);
            if ( pfn != NULL && func_contains(pfn, minea) )
            {
              // ok, we're in the same function
              pfn = get_fchunk(cur_addr);
              minea = pfn->start_ea;
            }
          }
        }
        if ( cur_addr < minea )
          break;

        if ( (this->*check[n])() )
        {
          found_insn = true;
          break;
        }
        if ( handle_mov() )
          continue;
        if ( !tried_farref && allow_farrefs )
        {
          // the prev insn didn't match, try a far ref
          cur_addr = farref_to_try;
          goto FARREF;
        }
        if ( failed )
          return false;
        jmsg("%a: can't be %d.", insn.ea, n);
        jmsg(" rA=%d%s rB=%d%s rC=%d%s rD=%d%s rE=%d%s\n",
                        r[1], spoiled[1] ? "*" : "",
                        r[2], spoiled[2] ? "*" : "",
                        r[3], spoiled[3] ? "*" : "",
                        r[4], spoiled[4] ? "*" : "",
                        r[5], spoiled[5] ? "*" : "");
        check_spoiled();
      }
      if ( !found_insn )
      {
        memcpy(r, rsaved, sizeof(r));
        memcpy(r_moved, msaved, sizeof(r_moved));
        if ( optional )
        {
          // it was an optional instruction;
          // restore spoiled too
          memcpy(spoiled, ssaved, sizeof(spoiled));
          goto SUCC;
        }
        return false;
      }
      eas[n] = insn.ea;
    }
    if ( eas[n] >= ea )
    {
      jmsg("%a: depends on %a\n", ea, eas[n]);
      return optional;
    }
    ea = eas[n];
    jmsg("%a: found %d\n", insn.ea, n);
  }
SUCC:
  bool ok = true;
  for ( int i=0; i < 2; i++ )
  {
    if ( depends[n][i] && !follow_tree(ea, depends[n][i]) )
    {
      ok = false;
      break;
    }
  }
  if ( !ok && optional && found_insn )
  { // we found an optional insn, try without it
    found_insn = false;
    eas[n] = BADADDR;
    ea = saved_ea;
    memcpy(spoiled, ssaved, sizeof(spoiled));
    memcpy(r_moved, msaved, sizeof(r_moved));
    memcpy(r, rsaved, sizeof(r));
    goto SUCC;
  }
  if ( ok )
  {
    jmsg("follow_tree(%d) - ok\n", n);
    memcpy(spoiled, ssaved, sizeof(spoiled));
  }
  return ok;
}

//----------------------------------------------------------------------
bool jump_pattern_t::match(const insn_t &_insn)
{
  insn = _insn;
  // unfortunately we can not do this in the constructor
  check[0x00] = &jump_pattern_t::jpi0;
  check[0x01] = &jump_pattern_t::jpi1;
  check[0x02] = &jump_pattern_t::jpi2;
  check[0x03] = &jump_pattern_t::jpi3;
  check[0x04] = &jump_pattern_t::jpi4;
  check[0x05] = &jump_pattern_t::jpi5;
  check[0x06] = &jump_pattern_t::jpi6;
  check[0x07] = &jump_pattern_t::jpi7;
  check[0x08] = &jump_pattern_t::jpi8;
  check[0x09] = &jump_pattern_t::jpi9;
  check[0x0a] = &jump_pattern_t::jpia;
  check[0x0b] = &jump_pattern_t::jpib;
  check[0x0c] = &jump_pattern_t::jpic;
  check[0x0d] = &jump_pattern_t::jpid;
  check[0x0e] = &jump_pattern_t::jpie;
  check[0x0f] = &jump_pattern_t::jpif;

  memset(skip, 0, sizeof(skip));
  memset(eas, -1, sizeof(eas));
  memset(r, -1, sizeof(r));
  memset(&r_moved[0], 0, sizeof(r_moved));

  ea_t ea = insn.ea;
  eas[0] = ea;
  failed = false;

  func_t *pfn = get_fchunk(ea);
  if ( pfn == NULL )
    pfn = get_prev_fchunk(ea);
  if ( pfn != NULL )
  {
    minea = pfn->start_ea;
  }
  else
  {
    segment_t *seg = getseg(ea);
    QASSERT(10183, seg != NULL);
    minea = seg->start_ea;
  }

  if ( !(this->*check[0])() )
    return false;

  while ( *roots )
  {
    memset(spoiled, 0, sizeof(spoiled));
    ea = eas[0];
    int n = *roots++;
    if ( !start_tree(ea, n) )
      return false;
    if ( !follow_tree(ea, n) || failed )
      return false;
  }
  ea_t start = eas[0];
  for ( int i=1; i < qnumber(eas); i++ )
    start = qmin(start, eas[i]);
  si->startea = start;
  return !failed;
}


//------------------------------------------------------------------------
void jump_pattern_t::mark_switch_insns(int last, int first)
{
#ifndef DEFINE_MARK_SWITCH_INSNS
  qnotused(last);
  qnotused(first);
#else
  for ( int i = first; i <= last; i++ )
  {
    ea_t ea = eas[i];
    if ( ea != BADADDR && !remote_code.has(ea) )
      mark_switch_insn(ea);
  }
#endif
}

//----------------------------------------------------------------------
bool jump_pattern_t::mov_set(uint16 reg, const op_t &op, bool spoil_reg)
{
  bool ok = false;
  for ( int i = 0; i < qnumber(r); i++ )
  {
    if ( r[i] == reg )
    {
      r_moved[i] = op;
      if ( spoil_reg )
        spoiled[i] = true;
      ok = true;
    }
  }
  return ok;
}

//----------------------------------------------------------------------
bool jump_pattern_t::is_same(const op_t &op, int r_i)
{
  if ( !spoiled[r_i] )
    return op.is_reg(r[r_i]);

  return op.type  == r_moved[r_i].type
      && op.reg   == r_moved[r_i].reg
      && op.value == r_moved[r_i].value
      && op.addr  == r_moved[r_i].addr;
}

//----------------------------------------------------------------------
static inline ea_t calc_entry_target(segment_t *seg, ea_t ea, const switch_info_t &si)
{
  sval_t off = 0;
  int jsize = si.get_jtable_element_size();
  bool is_signed = (si.flags & SWI_SIGNED) != 0;
  switch ( jsize )
  {
    case 1:
      off = get_byte(ea);
      if ( is_signed )
        off = char(off);
      break;
    case 2:
      off = get_word(ea);
      if ( is_signed )
        off = int16(off);
      break;
    case 4:
      off = get_dword(ea);
#ifdef __EA64__
      if ( is_signed )
        off = int32(off);
#endif
      break;
    case 8:
      off = (sval_t)get_qword(ea);
      break;
  }
  off <<= si.get_shift();
  if ( si.is_subtract() )
    off = -off;

  ea_t target = segm_adjust_ea(seg, (si.elbase == BADADDR ? 0 : si.elbase) + off);
  if ( ph.id == PLFM_ARM )
    target &= ~ea_t(1); // strip Thumb bit
  return target;
}

//----------------------------------------------------------------------
static bool is_coagulated_addr(ea_t ea)
{
  return was_ida_decision(get_item_head(ea));
}

//----------------------------------------------------------------------
// sometimes the size of the jump table is misdetected
// check if any of the would-be targets point into the table
// and if so, truncate it
// if 'ignore_refs' is false, also stop at first data reference
static inline void trim_jtable(switch_info_t *_si, bool ignore_refs = false)
{
  switch_info_t &si = *_si;
  unsigned int elsize = si.get_jtable_element_size();
  ea_t start  = si.jumps;
  ea_t end    = start + elsize * si.ncases;
  ea_t ea = start;
  if ( si.defjump != BADADDR && si.defjump > start && si.defjump < end )
    end = si.defjump; // table shouldn't overlap defjump
  segment_t *curseg = getseg(ea);
  while ( ea < end )
  {
    if ( !is_coagulated_addr(ea) )
    {
      flags_t F = get_full_flags(ea);
      if ( !has_value(F)
        || is_code(F)
        || (is_tail(F) && get_item_head(ea) != start)
        || (!ignore_refs && has_xref(F)) )
      {
        // for the start address, only truncate if there is no value
        // other situations are possibly caused by wrong analysis
        if ( ea != start || !has_value(F) )
        {
          //msg("%a: table would run into code; truncating it\n", ea);
          end = ea;
          break;
        }
      }
    }
    ea_t target = calc_entry_target(curseg, ea, si);
    if ( !is_coagulated_addr(target) )
    {
      flags_t F = get_full_flags(target);
      if ( !has_value(F) || is_data(F) || is_tail(F) )
      {
        //msg("%a: item would point to non-code; truncating it\n", ea);
        end = ea;
        break;
      }
    }
    if ( target < end )
    {
      //msg("%a: item would point into table; truncating it\n", ea);
      if ( target >= ea )
      {
        // we're pointing past the current item
        end = target;
        // restart the check, since the table is smaller now
        ea = start;
        continue;
      }
      else if ( target >= start )
      {
        // we're pointing before the current item,
        // into already processed items
        // truncate the table right here
        end = ea;
        break;
      }
    }
    ea += elsize;
  }
  int newn = (end - start) / elsize;
  if ( newn != si.ncases )
  {
    //msg("%a: table truncated from %d to %d cases\n", si.jumps, si.ncases, newn);
    si.ncases = newn;
  }
}

//----------------------------------------------------------------------
#ifndef SKIP_NOPC_FUNCTIONS
// check and create a flat 32/16/8 bit jump table -- the most common case
static void check_and_create_flat_jump_table(
        switch_info_t *_si,
        const insn_t &insn,
        jump_table_type_t /*jtt*/)
{
  switch_info_t &si = *_si;
  // check the table contents
  ea_t table = si.jumps;
  segment_t *table_seg = getseg(table);
  if ( table_seg == NULL )
    return;
  size_t maxsize = size_t(table_seg->end_ea - table);
  int size = si.ncases;
  if ( size > maxsize )
  {
    size = (int)maxsize;
    jmsg("Adjust ncases from %d to %d\n", si.ncases, size);
  }

  int elsz = si.get_jtable_element_size();

  int i;
  for ( i = 0; i < size; i++ )
  {
    ea_t ea = table + i*elsz;
    flags_t F = get_full_flags(ea);
    if ( !has_value(F) )
      break;
    if ( i && (has_any_name(F) || has_xref(F)) )
      break;
    ea_t target = calc_entry_target(table_seg, ea, si);
    if ( !is_loaded(target) )
      break;
    flags_t F2 = get_flags(target);
    if ( is_tail(F2) || is_data(F2) )
      break;
    if ( !is_code(F2) && !can_decode(target) )
      break;
  }
  jmsg("Adjust ncases from %d to %d\n", size, i);
  size = i;

  // create the table
  for ( i=0; i < size; i++ )
  {
    ea_t ea = table + i*elsz;
    if ( elsz == 1 )
      create_byte(ea, 1);
    else if ( elsz == 2 )
      create_word(ea, 2);
    else
      create_dword(ea, 4);
    op_offset(ea, 0, REF_OFF32, BADADDR, si.elbase);
    ea_t target = calc_entry_target(table_seg, ea, si);
    add_cref(insn.ea, target, fl_JN);
  }
  si.ncases = (uint16)size;
  if ( si.defjump != BADADDR )
    si.flags |= SWI_DEFAULT;
  if ( si.startea == BADADDR )
    si.startea = insn.ea;
  set_switch_info(insn.ea, si);
}

//----------------------------------------------------------------------
typedef void create_table_t(switch_info_t *si, const insn_t &insn, jump_table_type_t jtt);
typedef jump_table_type_t is_pattern_t(switch_info_t *si, const insn_t &insn);

// This function finds and creates a 32-bit jump table
static bool check_for_table_jump(
        switch_info_t *_si,
        const insn_t &insn,
        is_pattern_t *const patterns[],
        size_t qty,
        create_table_t *create_table=NULL,
        const char *name=NULL)
{
  switch_info_t &si = *_si;
  jump_table_type_t jtt = JT_NONE;
  size_t i;
  for ( i=0; jtt == JT_NONE && i < qty; i++ )
  {
    jmsg("%a: check pattern %" FMT_Z " ----\n", insn.ea, i);
    si.clear();
    jtt = patterns[i](&si, insn);
  }
  if ( jtt == JT_NONE )
    return false;

  jmsg("%s(%" FMT_Z "): jumps=%a lowcase=%" FMT_EA "d. ncases=%hd. elbase=%a defjump=%a\n",
       name == NULL ? "unknown" : name, i,
       si.jumps, si.lowcase, si.ncases, si.elbase, si.defjump);

  if ( si.elbase != BADADDR )
    si.flags |= SWI_ELBASE;

  if ( create_table == NULL )
    check_and_create_flat_jump_table(&si, insn, jtt);
  else
    create_table(&si, insn, jtt);

  char buf[MAXSTR];
  if ( si.defjump != BADADDR )
  {
    qsnprintf(buf, sizeof(buf), "def_%a", insn.ip);
    if ( !set_name(si.defjump, buf, SN_NOCHECK|SN_NOWARN|SN_LOCAL) )
      set_name(si.defjump, buf, SN_NOCHECK|SN_NOWARN);
  }
  qsnprintf(buf, sizeof(buf), "jpt_%a", insn.ip);
  set_name(si.jumps, buf, SN_NOCHECK|SN_NOWARN);
  return true;
}

#endif // SKIP_NOPC_FUNCTIONS
