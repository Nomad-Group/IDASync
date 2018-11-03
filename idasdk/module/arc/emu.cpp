/*
 *   Interactive disassembler (IDA).
 *   Copyright (c) 1990-98 by Ilfak Guilfanov.
 *   ALL RIGHTS RESERVED.
 *   E-mail: ig@estar.msk.su, ig@datarescue.com
 *   FIDO:    2:5020/209
 *
 */

#include <map>

#include "arc.hpp"
#include <frame.hpp>
#include <xref.hpp>

//#define DEBUG_ARGLOC

//----------------------------------------------------------------------
#ifdef DEBUG_ARGLOC
static void debug_print_argloc(int i, const argloc_t &argloc, const tinfo_t &type)
{
  qstring typestr;
  type.print(&typestr);
  char varstr[MAXSTR];
  if ( argloc.is_stkoff() )
    qsnprintf(varstr, sizeof(varstr), "STK_%x", int(argloc.stkoff()));
  else
    print_argloc(varstr, sizeof(varstr), argloc, type.get_size());
  if ( i == -1 )
    msg("RET: %s %s\n", typestr.c_str(), varstr);
  else
    msg("%d: %s %s\n", i, typestr.c_str(), varstr);
}
#else
inline void debug_print_argloc(int, const argloc_t &, const tinfo_t &) {}
#endif

static bool find_op_value(const insn_t &insn, const op_t &x, uval_t *p_val, ea_t *p_val_ea=NULL, bool check_fbase_reg=true, bool *was_const_load=NULL);

static int islast;

// does the expression [reg, xxx] point to the stack?
static bool is_stkptr(const insn_t &insn, int reg)
{
  if ( reg == SP )
    return true;
  if ( reg == FP )
  {
    func_t *pfn = get_func(insn.ea);

    if ( pfn != NULL && (pfn->flags & FUNC_FRAME) != 0 )
      return true;
  }
  return false;
}

static void handle_operand(const insn_t &insn, const op_t & x, int loading)
{
  flags_t F;
  switch ( x.type )
  {
    case o_reg:
      break;
    case o_imm:
      set_immd(insn.ea);
      F = get_flags(insn.ea);
      if ( op_adds_xrefs(F, x.n) )
      {
        insn.add_off_drefs(x, dr_O, OOFS_IFSIGN);
      }
      else if ( x.n == 2 && may_create_stkvars() && !is_defarg(F, x.n)
             && insn.itype == ARC_add && !insn.Op1.is_reg(SP) && !insn.Op1.is_reg(FP)
             && (insn.Op2.is_reg(SP) || insn.Op2.is_reg(FP)) )
      {
        // add rx, sp, #imm
        func_t *pfn = get_func(insn.ea);
        if ( pfn != NULL )
        {
          adiff_t sp_off = x.value;
          if ( insn.create_stkvar(x, sp_off, 0) )
            op_stkvar(insn.ea, x.n);
        }
      }
      break;
    case o_mem:
      if ( insn.itype != ARC_lr && insn.itype != ARC_sr )
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        insn.create_op_data(ea, x);         // create the data item of the correct size
        insn.add_dref(ea, x.offb, loading ? dr_R : dr_W);
        if ( (idpflags & ARC_INLINECONST) != 0 && insn.itype == ARC_ld )
          copy_insn_optype(insn, x, ea);
      }
      break;
    case o_near:
      {
        int iscall = has_insn_feature(insn.itype, CF_CALL);

        insn.add_cref(to_ea(insn.cs, x.addr), x.offb, iscall ? fl_CN : fl_JN);
        if ( !islast && iscall )
        {
          if ( !func_does_return(x.addr) )        // delay slot?!
            islast = 1;
        }
      }
      break;
    case o_displ:
      set_immd(insn.ea);
      F = get_flags(insn.ea);
      if ( !is_defarg(F, x.n) && x.reg == PCL )
      {
        op_offset(insn.ea, x.n, REF_OFF32|REFINFO_NOBASE, BADADDR, insn.ea & (~3ul));
      }
      if ( op_adds_xrefs(F, x.n) ) // create an xref for offset expressions
      {
        ea_t target = insn.add_off_drefs(x, loading ? dr_R : dr_W, OOF_ADDR|OOF_SIGNED|OOFW_32);
        if ( target != BADADDR )
          insn.create_op_data(target, x); // create the data item of the correct size
      }
      else if ( is_stkptr(insn, x.phrase) && may_create_stkvars() && !is_defarg(F, x.n) )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != NULL )
        {
          // if it's [sp, xxx] we make a stackvar out of it
          adiff_t sp_off = x.addr;
          if ( insn.create_stkvar(x, sp_off, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, x.n);
        }
      }
      break;
  }
}

//------------------------------------------------------------------------
bool idaapi equal_ops(const op_t &x, const op_t &y)
{
  if ( x.type != y.type )
    return false;
  switch ( x.type )
  {
    case o_void:        // No Operand                           ----------
      break;
    case o_reg:         // General Register                     reg
      if ( x.reg != y.reg )
        return false;
      break;
    case o_far:         // Immediate Far Address                addr+segrg+segsel
    case o_near:        // Immediate Near Address               addr+segrg+segsel
      if ( x.addr != y.addr )
        return false;
      break;
    case o_mem:         // Memory Reference                     addr+segrg+segsel+sib
      if ( x.addr != y.addr )
        return false;
      break;
    case o_displ:       // Base Reg + Index Reg + Displacement  phrase+addr+sib
      if ( x.addr != y.addr )
        return false;
      // no break
    case o_phrase:      // Base Reg + Index Reg                 phrase+sib
      if ( x.phrase != y.phrase )
        return false;
      if ( x.secreg != y.secreg )
        return false;
      break;
    case o_imm:         // Immediate                            value
      if ( x.value != y.value )
        return false;
      break;
  }
  return true;
}

//----------------------------------------------------------------------
inline bool is_callee_saved(int reg)
{
  return reg >= ARC_ABI_FIRST_CALLEE_SAVED_REGISTER
      && reg <= ARC_ABI_LAST_CALLEE_SAVED_REGISTER;
}

//----------------------------------------------------------------------
// Is register 'reg' spoiled by the current instruction?
static bool spoils(const insn_t &insn, int reg)
{
  switch ( insn.itype )
  {
    case ARC_pop:  // POP [reg] spoils it
      return insn.Op1.reg == reg || reg == SP;

    case ARC_push:
      return reg == SP;

    case ARC_ld:  // ld Rx, [reg, #imm]
      if ( insn.Op1.reg == reg )
        return true;
    // fall through

    case ARC_st:  // st.a R1, [R2, #imm]
      if ( insn.Op2.reg == reg && ((insn.auxpref & aux_amask) == aux_a || (insn.auxpref & aux_amask) == aux_ab) )
        return true;
      break;// otherwise check flags

    case ARC_bl:
    case ARC_jl:
      return !is_callee_saved(reg);
  }

  uint32 feature = insn.get_canon_feature();
  for ( int i=0; i < UA_MAXOP; i++ )
  {
    if ( (feature & (CF_CHG1<<i)) == 0 || insn.ops[i].type != o_reg )
      continue;
    int r = insn.ops[i].reg;
    if ( r == reg )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// has 'op' the same value as r1 or moved_op?
static bool same_reg_value(ea_t ea, const op_t &op, int r1, const op_t &moved_op)
{
  bool ok = false;
  if ( op.type == o_reg )
  {
    int r2 = op.reg;
    if ( r1 == r2 )
      return true;

    if ( moved_op.is_reg(r1) )
      return true;

    while ( !ok )
    {
      flags_t F = get_flags(ea);
      if ( has_xref(F) || !is_flow(F) )
        break;
      insn_t insn;
      if ( decode_prev_insn(&insn, ea) == BADADDR )
        break;
      switch ( insn.itype )
      {
        case ARC_add:                     // add r1, r2, 0 is the same as mov
        case ARC_lsl:
        case ARC_lsr:
        case ARC_sub:
        case ARC_xor:
        case ARC_or:
          if ( insn.Op1.type != o_reg
            || insn.Op2.type != o_reg
            || insn.Op3.type != o_imm
            || insn.Op3.value != 0 )
          {
            break;
          }
          // no break
        case ARC_mov:
          if ( insn.Op1.reg == r1 )
            r1 = insn.Op2.reg;
          if ( insn.Op1.reg == r2 )
            r2 = insn.Op2.reg;
          if ( r1 == r2 )
            ok = true;
          break;
        case ARC_ld:
          // LDR r2, [SP,#off]
          if ( insn.Op1.is_reg(r2) )
            ok = equal_ops(insn.Op2, moved_op);
          break;
      }
      if ( spoils(insn, r1) || spoils(insn, r2) )
        break;
    }
  }
  return ok;
}

// info about a single register
struct ldr_value_info_t
{
  uval_t value;         // value loaded into the register
  ea_t val_ea;          // where the value comes from (for constant pool or immediate loads)
  eavec_t insn_eas;     // insns that were involved in calculating the value
  char n;               // operand number
  char state;
#define LVI_STATE    0x03 // state mask
#define LVI_UNKNOWN  0x00 // unknown state
#define LVI_VALID    0x01 // value known to be valid
#define LVI_INVALID  0x02 // value known to be invalid
#define LVI_CONST    0x04 // is the value constant? (e.g. immediate or const pool)

  ldr_value_info_t(void)
    : value(0), val_ea(BADADDR), n(0), state(LVI_UNKNOWN)
  {}
  bool is_const(void) const { return (state & LVI_CONST) != 0; }
  bool is_valid(void) const { return (state & LVI_STATE) == LVI_VALID; }
  bool is_known(void) const { return (state & LVI_STATE) != LVI_UNKNOWN; }
  void set_valid(bool valid)
  {
    state &= ~LVI_STATE;
    state |= valid ? LVI_VALID : LVI_INVALID;
  }
  void set_const(void) { state |= LVI_CONST; }
};

//----------------------------------------------------------------------
// helper class for find_op_value/find_ldr_value
// we keep a cache of discovered register values to avoid unnecessary recursion
struct reg_tracker_t
{
  // map cannot store an array directly, so wrap it in a class
  struct reg_values_t
  {
    ldr_value_info_t regs[R60+1]; // values for registers R0 to R60 for a specific ea
  };

  typedef std::map<ea_t, reg_values_t> reg_values_cache_t;

  // we save both valid and invalid values into in the cache.
  reg_values_cache_t regcache;

  // use fbase register value if we're in a function
  bool check_fbase_reg;

  // recursive functions; they can call each other, so we limit the nesting level
  bool do_find_op_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level);
  bool do_find_ldr_value(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *p_lvi, int nest_level);
  bool do_calc_complex_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level);

  bool is_call_insn(const insn_t &insn) const;

  reg_tracker_t(bool _check_fbase_reg): check_fbase_reg(_check_fbase_reg) {}
};

//----------------------------------------------------------------------
bool reg_tracker_t::is_call_insn(const insn_t &insn) const
{
  switch ( insn.itype )
  {
    case ARC_bl:
      return true;

    case ARC_jl:
      if ( insn.Op1.reg != BLINK && insn.Op1.reg != ILINK1 && insn.Op1.reg != ILINK2 )
        return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool is_arc_call_insn(const insn_t &insn)
{
  reg_tracker_t tr(true);
  return tr.is_call_insn(insn);
}

//----------------------------------------------------------------------
bool reg_tracker_t::do_find_op_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level)
{
  switch ( x.type )
  {
    case o_reg:
      return do_find_ldr_value(insn, insn.ea, x.reg, lvi, nest_level);
    case o_imm:
      if ( lvi != NULL )
      {
        lvi->value = x.value & 0xFFFFFFFF;
        lvi->set_const();
        lvi->set_valid(true);
        lvi->insn_eas.push_back(insn.ea);
      }
      return true;
    case o_displ:
    case o_phrase:
      {
        ldr_value_info_t val2;
        if ( do_calc_complex_value(insn, x, &val2, nest_level+1) && val2.is_valid() )
        {
          if ( lvi != NULL )
          {
            *lvi = val2;
            if ( lvi->is_valid() )
              lvi->insn_eas.push_back(insn.ea);
          }
          return true;
        }
      }
      break;
    case o_mem:
      if ( lvi != NULL )
      {
        ea_t value = to_ea(insn.cs, x.addr);
        ea_t val_ea = BADADDR;
        if ( insn.itype == ARC_ld && insn.Op2.dtype == dt_dword )
        {
          val_ea = value;
          value = BADADDR;
          if ( is_loaded(val_ea) )
          {
            value = get_dword(val_ea);
            lvi->set_const();
            lvi->set_valid(true);
            lvi->insn_eas.push_back(insn.ea);
          }
        }
        lvi->val_ea = uint32(val_ea);
        lvi->value  = uint32(value);
      }
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
// check if ea is in a const segment, and so we can use the pointer value
static bool is_const_seg(ea_t ea)
{
  if ( !is_loaded(ea) )
    return false;

  const char *const *names = NULL;
  int ncnt = 0;
  if ( inf.filetype == f_MACHO )
  {
    static const char *const macho_segs[] =
    {
      "__const", "__const_coal",
      "__text", "__dyld",
      "__la_symbol_ptr", "__nl_symbol_ptr",
      "__class", "__cls_refs", "__message_refs",
      "__inst_meth", "__cat_inst_meth", "__cat_cls_meth",
      "__constructor", "__destructor", "__pointers",
      "__objc_protorefs",
      "__objc_selrefs",
      "__objc_classrefs",
      "__objc_superrefs",
      "__objc_const",
    };
    names = macho_segs;
    ncnt = qnumber(macho_segs);
  }
  else if ( inf.filetype == f_ELF )
  {
    static const char *const elf_segs[] =
    {
      ".got", ".text", ".rodata",
      ".got.plt", ".plt",
      ".init", ".fini"
    };
    names = elf_segs;
    ncnt = qnumber(elf_segs);
  }
  if ( names != NULL )
  {
    segment_t *seg = getseg(ea);
    if ( seg != NULL )
    {
      qstring segname;
      if ( get_segm_name(&segname, seg) > 0 )
      {
        for ( size_t i = 0; i < ncnt; i++ )
          if ( segname == names[i] )
            return true;
      }
    }
  }

  if ( segtype(ea) == SEG_CODE )
    return true;

  segment_t *seg = getseg(ea);
  if ( seg != NULL && (seg->perm & (SEGPERM_WRITE|SEGPERM_READ)) == SEGPERM_READ )
    return true;

  return false;
}

//----------------------------------------------------------------------
// calculate value of a complex operand
// ld    [<Rn>, #+/-<offset>]
// ld    [<Rn>, <Rm>]
// ld.a  [<Rn>, #+/-<offset>]
// ld.ab [<Rn>, #+/-<offset>] (post-increment)
// val_ea is always calculated, val only for dword accesses to const segments
// returns true is val_ea is ok; value may be still wrong! set is_valid() for the value
bool reg_tracker_t::do_calc_complex_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level)
{
  ldr_value_info_t val1;
  ea_t val_ea = BADADDR;
  uval_t value = BADADDR;
  bool ok = false;
  if ( do_find_ldr_value(insn, insn.ea, x.reg, &val1, nest_level+1) )
  {
    ldr_value_info_t val2;
    if ( (insn.auxpref & aux_amask) == aux_ab ) // post-increment
    {
      ok = true;
      val2.value = 0;
    }
    else
    {
      if ( x.type == o_phrase )
      {
        ok = do_find_ldr_value(insn, insn.ea, x.secreg, &val2, nest_level+1);
      }
      else if ( x.type == o_displ )
      {
        ok = true;
        val2.value = (int32)x.addr;
      }
      if ( !ok )
        return false;
    }
    val_ea = to_ea(insn.cs, val1.value + val2.value);
    if ( x.dtype == dt_dword && is_const_seg(val_ea) )
      value = get_dword(val_ea);
  }
  if ( ok && lvi != NULL )
  {
    lvi->value = uint32(value);
    if ( value != BADADDR )
      lvi->set_valid(true);
    lvi->val_ea = uint32(val_ea);
    lvi->n = x.n;
  }
  return ok;
}

//----------------------------------------------------------------------
bool reg_tracker_t::do_find_ldr_value(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *p_lvi, int nest_level)
{
  if ( nest_level > 200 )
    return false;
  bool ok = false;
  ldr_value_info_t lvi;
  do
  {
    if ( reg == PCL )
    {
      lvi.value = insn.ip & ~3ul;
      lvi.value &= 0xFFFFFFFF;
      lvi.set_valid(true);
      lvi.set_const();
      lvi.insn_eas.push_back(insn.ea);
      ok = true;
      break;
    }

    if ( reg >= R60 || reg < 0 )
    {
      // not handled
      break;
    }

    // check if it's in the cache
    reg_values_cache_t::iterator regs_it = regcache.find(ea);
    if ( regs_it != regcache.end() )
    {
      const ldr_value_info_t &cached = regs_it->second.regs[reg];
      if ( cached.is_known() )
      {
        ok = lvi.is_valid();
        if ( ok )
          lvi = cached;
        break;
      }
    }

    /*
    ushort fbase_reg;
    if ( check_fbase_reg && get_fbase_info(&lvi.value, &fbase_reg) && fbase_reg == reg )
    {
      lvi.value -= to_ea(insn.cs, 0);
      ok = true;
    }
    */

    const insn_t *pinsn = &insn;
    insn_t curr_insn;
    while ( !ok )
    {
      flags_t F = get_flags(pinsn->ea);
      if ( has_xref(F) || !is_flow(F) )
      {
        // count xrefs to the current instruction
        xrefblk_t xb;
        int numxrefs = 0;
        ea_t xref_from = BADADDR;
        for ( bool ok2 = xb.first_to(pinsn->ea, XREF_ALL);
              ok2 && numxrefs < 2;
              ok2 = xb.next_to() )
        {
          if ( xb.iscode && xb.from < pinsn->ea ) // count only xrefs from above
          {
            // call xref => bad
            if ( xb.type == fl_CN || xb.type == fl_CF )
            {
              numxrefs = 0;
              break;
            }
            xref_from = xb.from;
            numxrefs++;
          }
        }
        // if we have a single xref, use it
        if ( numxrefs != 1 || xref_from == BADADDR || decode_insn(&curr_insn, xref_from) == 0 )
          break;

      }
      else
      {
        if ( decode_prev_insn(&curr_insn, pinsn->ea) == BADADDR )
          break;
      }
      pinsn = &curr_insn;

      if ( cond(insn) != cAL ) // we started with a conditional instrucion?
      {
        // ignore instructions which belong to different condition branches
        if ( cond(*pinsn) != cAL || cond(*pinsn) != cond(insn) )
          continue;
        // if current instruction changes flags, stop tracking
        if ( pinsn->itype == ARC_cmp || pinsn->itype == ARC_flag || (pinsn->auxpref & aux_f) != 0 )
          break;
      }

      if ( pinsn->Op1.is_reg(reg) )
      {
        switch ( pinsn->itype )
        {
          case ARC_ld:
            if ( pinsn->Op2.type == o_mem && pinsn->Op2.dtype == dt_dword )
            {
              lvi.val_ea = to_ea(pinsn->cs, pinsn->Op2.addr);
              if ( is_loaded(lvi.val_ea) && is_const_seg(lvi.val_ea) )
              {
                lvi.value = get_dword(lvi.val_ea);
                lvi.set_const();
                ok = true;
              }
            }
            else if ( pinsn->Op2.type == o_displ || pinsn->Op2.type == o_phrase )
            {
              ok = do_calc_complex_value(*pinsn, pinsn->Op2, &lvi, nest_level+1) && lvi.is_valid();
            }
            if ( ok )
              lvi.insn_eas.push_back(pinsn->ea);
            break;
          case ARC_mov:
            ok = do_find_op_value(*pinsn, pinsn->Op2, &lvi, nest_level+1);
            if ( ok )
            {
              if ( pinsn->itype == ARC_mov && pinsn->Op2.type == o_imm )
              {
                // MOV Rx, #ABCD
                lvi.val_ea = pinsn->ea;
                lvi.n = 1;
              }
            }
            break;
          case ARC_asr:
          case ARC_lsl:
          case ARC_lsr:
          case ARC_ror:
          case ARC_and:
          case ARC_xor:
          case ARC_add:
          case ARC_sub:
          case ARC_rsub:
          case ARC_or:
          case ARC_bic:
            {
              ldr_value_info_t v1;
              ldr_value_info_t v2;
              const op_t *op1 = &pinsn->Op1;
              const op_t *op2 = &pinsn->Op2;
              if ( pinsn->Op3.type != o_void )
              { // arm mode
                op1++; // points to pinsn->Op2
                op2++; // points to pinsn->Op3
              }
              if ( !do_find_op_value(*pinsn, *op1, &v1, nest_level+1) )
                break;
              if ( !do_find_op_value(*pinsn, *op2, &v2, nest_level+1) )
                break;
              switch ( pinsn->itype )
              {
                case ARC_add:
                  lvi.value = v1.value + v2.value;
                  break;
                case ARC_sub:
                  lvi.value = v1.value - v2.value;
                  break;
                case ARC_rsub:
                  lvi.value = v2.value - v1.value;
                  break;
                case ARC_or:
                  lvi.value = v1.value | v2.value;
                  break;
                case ARC_asr:
                  lvi.value = ((int32)v1.value) >> v2.value;
                  break;
                case ARC_lsl:
                  lvi.value = v1.value << v2.value;
                  break;
                case ARC_lsr:
                  lvi.value = ((uint32)v1.value) >> v2.value;
                  break;
                case ARC_ror:
                  v2.value %= 32;
                  lvi.value = (v1.value >> v2.value) | (v1.value << (32-v2.value));
                  break;
                case ARC_and:
                  lvi.value = v1.value & v2.value;
                  break;
                case ARC_xor:
                  lvi.value = v1.value ^ v2.value;
                  break;
                case ARC_bic:
                  lvi.value = v1.value & ~v2.value;
                  break;
              }
              ok = true;
              if ( v1.is_const() && v2.is_const() )
                lvi.set_const();
              // we do not take into account the insns that calculate .got
              /*
              if ( got_ea == BADADDR || v1.value != got_ea )
                add_eavec(&lvi.insn_eas, v1.insn_eas);
              if ( got_ea == BADADDR || v2.value != got_ea )
                add_eavec(&lvi.insn_eas, v2.insn_eas);*/
              lvi.insn_eas.push_back(pinsn->ea);
            }
            break;
        }
      }
      else if ( (pinsn->itype == ARC_ld || pinsn->itype == ARC_st)
             && pinsn->Op2.type == o_displ && pinsn->Op2.reg == reg
             && ((pinsn->auxpref & aux_amask) == aux_a || (pinsn->auxpref & aux_amask) == aux_ab) )
      {
        // writeback of the base reg
        // find the previous value
        op_t x = pinsn->Op2;
        x.type = o_reg;
        ok = do_find_op_value(*pinsn, x, &lvi, nest_level+1);
        if ( ok )
        {
          // add the immediate
          lvi.value += pinsn->Op2.addr;
          lvi.insn_eas.push_back(pinsn->ea);
        }
      }
      if ( spoils(*pinsn, reg) )
        break;
    }
#ifdef __EA64__
    lvi.value &= 0xFFFFFFFF;
#endif
    lvi.set_valid(ok);
    regcache[ea].regs[reg] = lvi;
  }
  while ( false );

  if ( ok && p_lvi != NULL )
    *p_lvi = lvi;
  return ok;
}

//----------------------------------------------------------------------
static bool find_op_value_ex(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, bool check_fbase_reg)
{
  reg_tracker_t tr(check_fbase_reg);
  return tr.do_find_op_value(insn, x, lvi, 0);
}

//----------------------------------------------------------------------
// find the value loaded into reg
static bool find_ldr_value_ex(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *lvi, bool check_fbase_reg)
{
  reg_tracker_t tr(check_fbase_reg);
  return tr.do_find_ldr_value(insn, ea, reg, lvi, 0);
}

//----------------------------------------------------------------------
static bool find_op_value(const insn_t &insn, const op_t &x, uval_t *p_val, ea_t *p_val_ea, bool check_fbase_reg, bool *was_const_load)
{
  ldr_value_info_t tmp;
  if ( find_op_value_ex(insn, x, &tmp, check_fbase_reg) )
  {
    if ( p_val != NULL )
      *p_val = tmp.value;
    if ( p_val_ea != NULL )
      *p_val_ea = tmp.val_ea;
    if ( was_const_load != NULL )
      *was_const_load = tmp.is_const();
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool find_ldr_value(const insn_t &insn, ea_t ea, int reg, uval_t *p_val, ea_t *p_val_ea=NULL, bool check_fbase_reg=true, bool *was_const_load=NULL)
{
  ldr_value_info_t tmp;
  if ( find_ldr_value_ex(insn, ea, reg, &tmp, check_fbase_reg) )
  {
    if ( p_val != NULL )
      *p_val = tmp.value;
    if ( p_val_ea != NULL )
      *p_val_ea = tmp.val_ea;
    if ( was_const_load != NULL )
      *was_const_load = tmp.is_const();
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
#include "../jptcmn.cpp"

struct arc_jump_pattern_t : public jump_pattern_t
{
  arc_jump_pattern_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : jump_pattern_t(_si, _roots, _depends) {}
  eavec_t extra_insn_eas; // extra insns used to calculate values
                          // (discovered by find_ldr_value_ex)
  virtual void mark_switch_insns(int /*last*/, int /*first = 1*/)
  {
    // in addition to the regular insns discovered by the pattern matcher, mark
    // the insns found by find_ldr_value_ex()
    /*jump_pattern_t::mark_switch_insns(last, first);
    for ( eavec_t::iterator p = extra_insn_eas.begin(); p != extra_insn_eas.end(); ++p )
      mark_switch_insn(*p);*/
  }
};

//----------------------------------------------------------------------
// ARCompact ldb/ldw/ld switch
// 7      sub     Ra, Ra, #minv (optional)
// 6      cmp     Ra, #size
// 5      bls     L3
// 4      bcs|bhi default | b default
// 3  L3: add     Rtbl, pcl, #imm
// 2      ldb.x   Rb, [Rtbl,Ra]
// 1      add1    Rc, Rtbl, Rb
// 0      j       [Rc]
//jt      DCB bytes...
//
// 0 -> 1 -> 2 -> 3
//             -> 6 -> 7
// 4 -> 5 -> 6 -> 7

static const char root1[] = { 1, 4, 0 };
static const char depend1[][2] =
{
  { 1 },        // 0
  { 2 },        // 1
  { 3, 6 },     // 2
  { 0 },        // 3
  { 5 },        // 4
  { 6 },        // 5
  { -7 },       // 6
  { 0 },        // 7 optional
};

class jump_pattern1_t : public arc_jump_pattern_t
{
protected:
  enum { rA=1, rB, rC, rTbl };
  jump_pattern1_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : arc_jump_pattern_t(_si, _roots, _depends)
  {
    allow_noflows = false;
  }
public:
  jump_pattern1_t(switch_info_t *_si) : arc_jump_pattern_t(_si, root1, depend1)
  {
    allow_noflows = false;
  }
  virtual bool jpi7(void); //     sub     Ra, Ra, #minv (optional)
  virtual bool jpi6(void); //     cmp     Ra, #size
  virtual bool jpi5(void); //     bls     L3
  virtual bool jpi4(void); //     bcs|bhi default | b default
  virtual bool jpi3(void); // L3: add     Rtbl, pcl, #imm
  virtual bool jpi2(void); //     ldb.x   Rb, [Rtbl,Ra]
  virtual bool jpi1(void); //     add1    Rc, Rtbl, Rb (optional)
  virtual bool jpi0(void); //     j       [Rc]
  // bool check_switch_ldr(bool is_ldrb);
  bool _jpi4(int n);
  bool _jpi5(int numins);
  bool _jpi6(int skip1, int skip2); // cmp Ra, #size | br.nc ra, #size, default
  bool handle_mov();
  bool is_branch_to(ea_t addr_to);
  virtual bool start_tree(ea_t, int n)
  {
    if ( n != 1 )
      allow_farrefs = false;
    return true;
  }
};

//----------------------------------------------------------------------
bool jump_pattern1_t::is_branch_to(ea_t addr_to)
{
  return insn.itype == ARC_b
      && cond(insn) == cAL
      && insn.Op1.addr == addr_to;
}

//----------------------------------------------------------------------
bool jump_pattern1_t::handle_mov(void)
{
  if ( insn.itype != ARC_mov && insn.itype != ARC_ld )
    return false;
  if ( insn.Op1.type != o_reg )
    return false;
  // we handle only registers and stkvars
  if ( (insn.Op2.type != o_displ || insn.Op2.phrase != SP)
    && insn.Op2.type != o_reg )
  {
    return false;
  }
  return mov_set(insn.Op1.reg, insn.Op2);
}

bool jump_pattern1_t::jpi7(void) // sub Ra, Ra, #minv (optional)
{
  if ( cond(insn) != cAL
    || insn.itype != ARC_sub
    || spoiled[rA]
    || !insn.Op1.is_reg(r[rA]) )
  {
    return false;
  }

  if ( insn.Op2.type == o_reg && insn.Op3.type == o_imm )
  {
    si->lowcase = insn.Op3.value;
    si->set_expr(insn.Op2.reg, insn.Op2.dtype);
  }
  else
  {
    if ( insn.Op2.type != o_imm )
      return false;
    si->lowcase = insn.Op2.value;
    si->startea = insn.ea;
  }

  // sometimes there is another SUB Ra, Rx, #minv2
  // just before the first SUB
  /*
  insn_t insn1;
  if ( decode_prev_insn(&insn1, insn.ea) != BADADDR
    && insn1.itype == ARC_sub
    && insn1.Op1.is_reg(r[rA])
    && insn1.Op2.type == o_reg
    && insn1.Op3.type == o_imm )
  {
    si->lowcase += insn1.Op3.value;
    si->set_expr(insn1.Op2.reg, insn1.Op2.dtype);
    r[rA] = insn1.Op2.reg;
    si->startea = insn1.ea;
  } */
  return true;
}

bool jump_pattern1_t::_jpi6(int skip1, int skip2) // cmp Ra, #size | br.nc ra, #size, default
{
  if ( cond(insn) != cAL
    || (insn.itype != ARC_cmp && insn.itype != ARC_and)
    || r[rA] == -1
    || (r[rA] != r[rB] && spoiled[rA])
    || !same_reg_value(insn.ea, insn.Op1, r[rA], r_moved[rA]) )
  {
    // br.nc ra, #size, default
    if ( insn.itype != ARC_br
      || spoiled[rA]
      || !insn.Op1.is_reg(r[rA])
      || insn.Op2.type != o_imm
      || cond(insn) != cNC )
      return false;

    si->ncases = ushort(insn.Op2.value);
    si->set_expr(insn.Op1.reg, insn.Op1.dtype);
    si->startea = insn.ea;
    si->defjump = insn.Op3.addr;
    if ( skip1 != -1 )
      skip[skip1] = true;
    if ( skip2 != -1 )
      skip[skip2] = true;
    return true;
  }

  op_t &expop = insn.Op1;
  if ( insn.itype == ARC_cmp )
  {
    if ( insn.Op2.type == o_imm )
      si->ncases = ushort(insn.Op2.value);
    /*else if ( insn.Op2.type == o_reg )
    {
      // cmp Ra, Rx
      uval_t value;
      if ( !find_ldr_value(insn, insn.ea, insn.Op2.reg, &value) )
        return false;
      si->ncases = (ushort)value;
    }*/
    else
      return false;
  }
  else
  {
    ushort n;
    if ( insn.Op2.type == o_reg && insn.Op3.type == o_imm )        // ANDS Ra, Rb, #3
    {
      expop = insn.Op2;
      n = ushort(insn.Op3.value);
    }
    else if ( insn.Op2.type == o_imm && insn.Op3.type == o_void )  // ANDS Ra, #3
    {
      n = ushort(insn.Op2.value);
    }
    else
    {
      return false;
    }
    // check that n+1 is a power of 2
    if ( n & (n+1) )
      return false;
    si->ncases = n+1;
  }
  si->set_expr(expop.reg, expop.dtype);
  si->startea = insn.ea;
  return true;
}

bool jump_pattern1_t::jpi6() // cmp Ra, #size | br.nc ra, #size, default
{
  return _jpi6(5, 4);
}

bool jump_pattern1_t::_jpi5(int) // bls L3
{
  if ( insn.itype != ARC_b )
    return false;
  if ( cond(insn) != cCC && cond(insn) != cLS )
    return false;
  if ( insn.Op1.addr <= insn.ea )
    return false;
  if ( cond(insn) == cLS )
    si->ncases++;
  return true;
}

bool jump_pattern1_t::jpi5(void)
{
  return _jpi5(3);
}

bool jump_pattern1_t::_jpi4(int n) // b default | bhi     default
{
  // allow_noflows = true;
  if ( insn.itype != ARC_b )
    return false;

  if ( cond(insn) == cHI || cond(insn) == cCS || cond(insn) == cGE || cond(insn) == cGT )
  {
    if ( cond(insn) == cHI || cond(insn) == cGT )
      si->ncases++;
    skip[n] = true;
  }
  else if ( (cond(insn) == cLS || cond(insn) == cCC || cond(insn) == cLT || cond(insn) == cLE) && insn.Op1.addr <= eas[3] )
  {
    // we have BLS to the switch instruction
    // followed by B default
    insn_t insn1;
    bool ok = decode_insn(&insn1, insn.ea + insn.size) > 0 /*&& cond(insn) == cAL && _jpi4(n)*/;
    if ( ok )
    {
      if ( (insn.auxpref & aux_cmask) == cLS || (insn.auxpref & aux_cmask) == cLE )
        si->ncases++;
      if ( cond(insn) == cAL && insn1.itype == ARC_b ) // b default
        si->defjump = insn1.Op1.addr;
      else
        si->defjump = insn1.ip;
      skip[n] = true;
    }
    return ok;
  }
  else if ( cond(insn) != cAL )
  {
    return false;
  }

  ea_t jump_ip;
  /*if ( insn.itype == ARC_br )
  {
    if ( !find_ldr_value(insn, insn.ea, insn.Op1.reg, &jump_ip) )
      return false;
    jump_ip &= ~1;
  }
  else*/
  {
    jump_ip = insn.Op1.addr;
  }
  si->defjump = jump_ip;
  return true;
}

bool jump_pattern1_t::jpi4(void) { return _jpi4(5); }

bool jump_pattern1_t::jpi3(void) // add Rtbl, pcl, #imm
{
  if ( cond(insn) != cAL
    || insn.itype != ARC_add
    || spoiled[rTbl]
    || !insn.Op1.is_reg(r[rTbl])
    || !insn.Op2.is_reg(PCL)
    || insn.Op3.type != o_imm )
  {
    return false;
  }
  ea_t pcval = insn.ip & ~3;
  si->jumps = pcval + insn.Op3.value;
  si->flags |= (si->defjump == BADADDR ? 0 : SWI_DEFAULT) | SWI_ELBASE;
  // si->set_jtable_element_size(jtt == JT_ARM_LDRB ? 1 : 2);
  si->elbase = si->jumps;
  return true;
}

// ldb.x   Rb, [Rtbl,Ra]
// ldw.x.as  Rb, [Rtbl,Ra]
// ld.as   Rb, [Rtbl,Ra]
bool jump_pattern1_t::jpi2()
{
  if ( eas[1] == BADADDR ) // add1 Rc, Rtbl, Rb was missing
    r[rB] = r[rC];

  if ( insn.itype != ARC_ld
    || spoiled[rB]
    || !insn.Op1.is_reg(r[rB])
    || insn.Op2.type != o_phrase
    || insn.Op2.reg != r[rTbl] )
  {
    return false;
  }

  if ( (insn.auxpref & aux_x) != 0 )
    si->flags |= SWI_SIGNED;

// ld.as  Rb, [Rtbl,Ra]
  if ( (insn.auxpref & (aux_zmask|aux_amask)) == (aux_l|aux_as) )
    si->set_jtable_element_size(4);
// ldb.x  Rb, [Rtbl,Ra]
  else if ( (insn.auxpref & (aux_zmask|aux_amask)) == (aux_b|aux_anone) )
    si->set_jtable_element_size(1);
// ldw.x.as  Rb, [Rtbl,Ra]
  else if ( (insn.auxpref & (aux_zmask|aux_amask)) == (aux_w|aux_as) )
    si->set_jtable_element_size(2);
  else
    return false;

  r[rA] = insn.Op2.secreg;
  return true;
}

bool jump_pattern1_t::jpi1(void) // add1    Rc, Rtbl, Rb
{
  if ( cond(insn) == cAL
    && !spoiled[rC]
    && insn.Op1.is_reg(r[rC]) )
  {
    if ( (insn.itype == ARC_add1 || insn.itype == ARC_add2 || insn.itype == ARC_add)
      && insn.Op2.type == o_reg
      && insn.Op3.type == o_reg )
    {
      if ( insn.itype == ARC_add1 )
        si->set_shift(1);
      else if ( insn.itype == ARC_add2 )
        si->set_shift(2);
      r[rTbl] = insn.Op2.reg;
      r[rB]   = insn.Op3.reg;
      return true;
    }
  }
  return false;
}

bool jump_pattern1_t::jpi0(void) // j [Rc]
{
  if ( cond(insn) != cAL || insn.itype != ARC_j )
    return false;

  r[rC] = insn.Op1.reg;
  return true;
}

//----------------------------------------------------------------------
// Absolute offsets
// 5      sub     Ra, Ra, #minv (optional)
// 4      cmp     Ra, #size               | br.nc ra, #size, default
// 3      bls     L3
// 2      bcs|bhi default | b default
// 1  L3: ld.as   Rb, [#addr,Ra]
// 0      j       [Rb]
//jt      DCB bytes...
//
// 0 -> 1 -> 4 -> 5
// 2 -> 3 -> 4 -> 5

static const char root2[] = { 1, 2, 0 };
static const char depend2[][2] =
{
  { 1 },        // 0
  { 4 },        // 1
  { 3 },        // 2
  { 4 },        // 3
  { -5 },       // 4
  { 0 },        // 5 optional
};

class jump_pattern2_t : public jump_pattern1_t
{
protected:
  jump_pattern2_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : jump_pattern1_t(_si, _roots, _depends)
  {
  }
public:
  jump_pattern2_t(switch_info_t *_si) : jump_pattern1_t(_si, root2, depend2)
  {
  }
  virtual bool jpi5(void)  //     sub     Ra, Ra, #minv (optional)
  {
    return jump_pattern1_t::jpi7();
  }
  virtual bool jpi4(void);  //     cmp     Ra, #size
  virtual bool jpi3(void)   //     bls     L3
  {
    return _jpi5(1);
  }
  virtual bool jpi2(void)  //     bcs|bhi default | b default
  {
    return _jpi4(3);
  }
  virtual bool jpi1(void); //     ld.as   Rc, [#table,Ra]
  // virtual bool jpi0(void)  //     j       [Rc]
  // bool check_switch_ldr(bool is_ldrb);
};

bool jump_pattern2_t::jpi4(void)
{
  return jump_pattern1_t::_jpi6(2, 3);
}

// ld.as   Rc, [#tbl,Ra]
bool jump_pattern2_t::jpi1()
{
  if ( insn.itype != ARC_ld
    || spoiled[rC]
    || !insn.Op1.is_reg(r[rC])
    || insn.Op2.type != o_displ
    || insn.Op2.membase == 0
    || (insn.auxpref & (aux_zmask|aux_amask)) != (aux_l|aux_as) )
  {
    return false;
  }

  si->set_jtable_element_size(4);

  si->jumps = insn.Op2.addr;
  // si->flags |= (si->defjump == BADADDR ? 0 : SWI_DEFAULT);
  // si->set_jtable_element_size(jtt == JT_ARM_LDRB ? 1 : 2);
  si->elbase = 0;
  r[rA] = insn.Op2.reg;
  return true;
}

//----------------------------------------------------------------------
static jump_table_type_t is_jump_pattern1(switch_info_t *si, const insn_t &insn)
{
  jump_pattern1_t jp(si);
  if ( jp.match(insn) )
  {
    // jp.mark_switch_insns(3);
    si->flags |= SWI_HXNOLOWCASE;
    return si->get_shift() == 1 ? JT_ARM_LDRB : JT_ARM_LDRH;
  }
  return JT_NONE;
}

//----------------------------------------------------------------------
static jump_table_type_t is_jump_pattern2(switch_info_t *si, const insn_t &insn)
{
  jump_pattern2_t jp(si);
  if ( jp.match(insn) )
  {
    // jp.mark_switch_insns(3);
    si->flags |= SWI_HXNOLOWCASE;
    return JT_ARM_LDRH;
  }
  return JT_NONE;
}

//----------------------------------------------------------------------
static void create_align_before_table(ea_t table)
{
  if ( get_byte(table-1) == 0
    && is_unknown(get_flags(table-1))
    && get_byte(table-2) == 0
    && is_unknown(get_flags(table-2)) )
  {
    create_align(table-2, 2, 2);
  }
}

//----------------------------------------------------------------------
// TODO: handle align for byte table in ARM mode (align = 4 bytes)
static void create_align_after_table(ea_t end)
{
  if ( (end & 1) != 0           // odd address
    && get_byte(end) == 0 )
  {
    del_items(end, DELIT_SIMPLE);
    create_align(end, 1, 1);
  }
}

//----------------------------------------------------------------------
static void create_jump_table(switch_info_t *_si, const insn_t &, jump_table_type_t jtt)
{
  switch_info_t &si = *_si;
  ea_t table = si.jumps;
  create_align_before_table(table);
  if ( jtt == JT_ARM_LDRB )
    create_align_after_table(table+si.ncases);

  si.flags |= (si.defjump == BADADDR ? 0 : SWI_DEFAULT) | SWI_ELBASE | SWI_SEPARATE;
  // si.set_jtable_element_size(jtt == JT_ARM_LDRB ? 1 : 2);
  // si.elbase = insn.ea + (is_thumb_ea(insn.ea) ? 4 : 8);
}

//----------------------------------------------------------------------
static bool arc_check_for_table_jump(switch_info_t *si, const insn_t &insn)
{
  static is_pattern_t *const patterns[] =
  {
    is_jump_pattern1,
    is_jump_pattern2,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns), create_jump_table);
}

//----------------------------------------------------------------------
bool arc_is_switch(const insn_t &insn)
{
  switch_info_t si;
  bool ok = (get_flags(insn.ea) & FF_JUMP) != 0
         && get_switch_info(&si, insn.ea) > 0;
  if ( !ok )
  {
    switch ( insn.itype )
    {
      case ARC_j:
        ok = arc_check_for_table_jump(&si, insn);
        break;
    }
    if ( ok )
    {
      set_switch_info(insn.ea, si);
      create_switch_table(insn.ea, si);
      create_switch_xrefs(insn.ea, si);
    }
  }
  return ok;
}

//----------------------------------------------------------------------
// Add a SP change point. We assume that SP is always divisible by 4
inline void add_stkpnt(const insn_t &insn, func_t *pfn, sval_t v)
{
  add_auto_stkpnt(pfn, insn.ea+insn.size, v);
}

//----------------------------------------------------------------------
// Trace the value of the SP and create an SP change point if the current
// instruction modifies the SP.
static void trace_sp(const insn_t &insn)
{
  if ( cond(insn) != cAL )        // trace only unconditional instructions
    return;                       // conditional instructions may be
                                  // corrected manually
  func_t *pfn = get_func(insn.ea);
  if ( pfn == NULL )
    return;                     // no function -> we don't care about SP

  switch ( insn.itype )
  {
    case ARC_add:
    case ARC_sub:
      if ( insn.Op1.is_reg(SP) )
      {
        if ( insn.Op2.is_reg(SP) )
        {
          // add sp, sp, #imm
          // add sp, sp, r1
          uval_t spofs;
          if ( find_op_value(insn, insn.Op3, &spofs, NULL, false) && (spofs & 3) == 0 )
            add_stkpnt(insn, pfn, int32(insn.itype == ARC_sub ? -spofs : spofs));
        }
      }
      break;
    case ARC_push:              // push [reg]
      add_stkpnt(insn, pfn, -4);
      break;
    case ARC_pop:               // pop  [reg]
      add_stkpnt(insn, pfn, +4);
      break;
    case ARC_ld:                // ld.ab   fp, [sp,4]
    case ARC_st:                // st.a    fp, [sp,-4]
      if ( insn.Op2.type == o_displ
        && insn.Op2.reg == SP
        && ((insn.auxpref & aux_amask) == aux_a || (insn.auxpref & aux_amask) == aux_ab) )
      {
        if ( (insn.Op2.addr & 3) == 0 )
          add_stkpnt(insn, pfn, insn.Op2.addr);
      }
      break;
    case ARC_bl:                // bl      __ac_push_13_to_NN: push 13..NN
    case ARC_b:                 // b       __ac_pop_13_to_NN:  pop 13..NN,blink
      {
        ea_t call_ea = to_ea(insn.cs, insn.Op1.addr);
        qstring namebuf;
        if ( get_name(&namebuf, call_ea) <= 0 )
          break;
        bool is_push;
        const char *name = namebuf.begin();
        if ( insn.itype == ARC_bl && strneq(name, "__ac_push", 9) )
        {
          is_push = true;
          name += 9;
        }
        else if ( insn.itype == ARC_b && strneq(name, "__ac_pop", 8) )
        {
          is_push = false;
          name += 8;
        }
        else if ( namebuf == "__ac_mc_va" || namebuf == "_stack_vargs" )
        {
          add_stkpnt(insn, pfn, -8*4);
          break;
        }
        else
        {
          break;
        }
        int from;
        int to;
        if ( qsscanf(name, "_%d_to_%d", &from, &to) != 2 )
          break;
        int nregs = to - from + 1;
        sval_t delta = 4 * (is_push ? (-nregs) : (nregs+1));
        add_stkpnt(insn, pfn, delta);
      }
      break;
    default:
      if ( insn.Op1.is_reg(SP) && insn.itype != ARC_mov )
      {
        // msg("??? illegal access mode sp @ %a\n", insn.ea);
      }
      break;
  }
}

//--------------------------------------------------------------------------
// is the input file object file?
// in such files, the references will be fixed up by the linker
static bool is_object_file(void)
{
  // Currently we know only about ELF relocatable files
  if ( inf.filetype == f_ELF )
  {
    char buf[MAXSTR];
    if ( get_file_type_name(buf, sizeof(buf)) > 0
      && stristr(buf, "reloc") != NULL ) // ELF (Relocatable)
    {
      return true;
    }
  }

  return false;
}

//--------------------------------------------------------------------------
// force the offset by the calculated base
static void force_offset(ea_t ea, int n, ea_t base, bool issub = false)
{
  if ( !is_off(get_flags(ea), n)
    || !is_object_file() && get_offbase(ea, n) != base )
  {
    refinfo_t ri;
    ri.init(REF_OFF32|REFINFO_NOBASE|(issub ? REFINFO_SUBTRACT : 0), base);
    op_offset_ex(ea, n, &ri);
  }
}

//--------------------------------------------------------------------------
// add resolved target address, to be displayed as a comment
inline void add_dxref(const insn_t &insn, ea_t target)
{
  // only add it if the comment would not be displayed otherwise
  // ASCII xrefs show up as comments
  if ( (inf.strlit_flags & STRF_COMMENT) && is_strlit(get_flags(target)) )
    return;

  // repeatable comments follow xrefs
  if ( get_cmt(NULL, target, true) > 0 )
    return;

  // demangled names show as comments
  // FIXME: get rid of GN_INSNLOC
#define MY_GN_INSNLOC 0x0080
  if ( get_demangled_name(NULL, target, inf.short_demnames,
                          DEMNAM_CMNT, GN_STRICT|MY_GN_INSNLOC) > 0 )
    return;

  set_dxref(insn.ea, target);
}

//----------------------------------------------------------------------
static bool is_good_target(ea_t ea)
{
  // address must exist
  if ( !is_mapped(ea) )
    return false;

  flags_t F = get_flags(ea);
  if ( !is_code(F) )
    return true;

  // don't point into middle of instructions
  return !is_tail(F);
}

//----------------------------------------------------------------------
// Emulate an instruction
int idaapi emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();

  islast = Feature & CF_STOP;

  ea_t cmdend = insn.ea + insn.size;

  if ( helper.altval_ea(insn.ea, DSLOT_TAG) == 1 )
    islast = 1; // previous instruction was an unconditional jump/branch

  // you may emulate selected instructions with a greater care:
  switch ( insn.itype )
  {
    case ARC_j:
      arc_is_switch(insn);
      // no break
    case ARC_b:
      if ( cond(insn) == cAL ) // branch always
        islast = 1;
      break;
    case ARC_add:                     // add r1, r2, #imm
    case ARC_sub:                     // sub r1, r2, #imm
      if ( (idpflags & ARC_TRACKREGS) != 0
        && insn.Op1.type == o_reg
        && !is_stkptr(insn, insn.Op2.reg)
        && !is_defarg(get_flags(insn.ea), 2) )
      {
        bool issub = insn.itype == ARC_sub;
        ea_t val1 = BADADDR;
        if ( find_op_value(insn, insn.Op2, &val1) && val1 != 0 )
        {
          if ( insn.Op3.type == o_imm && insn.Op3.value > 3 && is_good_target(val1 + insn.Op3.value) )
          {
            force_offset(insn.ea, 2, val1, issub);
          }
          else if ( insn.Op2.reg != insn.Op3.reg )
          {
            // mov  r12, #imm
            // sub  r3, r15, r12
            ldr_value_info_t lvi;
            if ( find_op_value_ex(insn, insn.Op3, &lvi, false) && lvi.value > 3 )
            {
              ea_t target = issub ? (val1 - lvi.value) : (val1 + lvi.value);
              if ( is_good_target(target) )
              {
                force_offset(lvi.val_ea, lvi.n, val1, issub);
                add_dxref(insn, target & 0xFFFFFFFF);
              }
            }
          }
        }
      }
      break;
    case ARC_ld:                      // ld r1, [r2, #imm]
    case ARC_st:                      // st r1, [r2, #imm]
      if ( (idpflags & ARC_TRACKREGS) != 0
        && insn.Op2.type == o_displ
        && !is_stkptr(insn, insn.Op2.reg)
        && !is_defarg(get_flags(insn.ea), 1) )
      {
        ea_t val1 = BADADDR;
        if ( insn.Op2.addr > 3 && find_ldr_value(insn, insn.ea, insn.Op2.reg, &val1) && val1 != 0 )
        {
           if ( (insn.auxpref & aux_amask) == aux_ab ) // post-increment
             val1 -= insn.Op2.addr;
           if ( is_good_target(val1 + insn.Op2.addr) )
             force_offset(insn.ea, 1, val1);
        }
      }
      break;
  }

  // trace the stack pointer if:
  //   - it is the second analysis pass
  //   - the stack pointer tracing is allowed
  if ( may_trace_sp() )
  {
    if ( !islast )
      trace_sp(insn);           // trace modification of SP register
    else
      recalc_spd(insn.ea);       // recalculate SP register for the next insn
  }

  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, 1);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, 1);
  if ( Feature & CF_USE3 )
    handle_operand(insn, insn.Op3, 1);

  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, 0);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, 0);
  if ( Feature & CF_CHG3 )
    handle_operand(insn, insn.Op3, 0);

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.

  if ( !islast || has_dslot(insn) )
    add_cref(insn.ea, cmdend, fl_F);
  else if ( get_auto_state() == AU_USED )
    recalc_spd(insn.ea);

  if ( has_dslot(insn) )
  {
    // mark the following address as a delay slot
    int slotkind;
    if ( insn.itype == ARC_bl || insn.itype == ARC_jl )
      slotkind = 3;
    else
      slotkind = islast ? 1 : 2;
    helper.altset_ea(cmdend, slotkind, DSLOT_TAG);
  }
  else
  {
    helper.altdel_ea(cmdend, DSLOT_TAG);
  }
  return 1;                     // actually the return value is unimportant, but let's it be so
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t * pfn)
{
  ea_t ea = pfn->start_ea;

  insn_t insn;
  for ( int i = 0; i < 10 && ea < pfn->end_ea; i++ )
  {
    if ( !decode_insn(&insn, ea) )
      break;
    // move fp, sp
    if ( insn.itype == ARC_mov
      && insn.Op1.is_reg(FP)
      && insn.Op2.is_reg(SP) )
    {
      pfn->flags |= FUNC_FRAME;
      update_func(pfn);
    }
    // sub sp, sp
    if ( insn.itype == ARC_sub
      && insn.Op1.is_reg(SP)
      && insn.Op2.is_reg(SP)
      && insn.Op3.type == o_imm )
    {
      return add_frame(pfn, insn.Op3.value, 0, 0);
    }
    ea += insn.size;
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &insn, const op_t & x)
{
  int flag = OP_FP_BASED;
  if ( x.type == o_displ && x.reg == SP
    || (x.type == o_imm && x.n == 2 && insn.itype == ARC_add && !insn.Op2.is_reg(FP)) )
  {
    // add rx, sp, #imm
    flag = OP_SP_BASED;
  }
  return OP_SP_ADD | flag;
}

//----------------------------------------------------------------------
int idaapi arc_get_frame_retsize(const func_t * /*pfn */ )
{
  return 0;
}

// #processor_t.is_align_insn
//----------------------------------------------------------------------
// Is the instruction created only for alignment purposes?
// returns: number of bytes in the instruction
int idaapi is_align_insn(ea_t ea)
{
  if ( ptype == prc_arcompact )
  {
    if ( (ea & 3) != 0 )
      return 0;
    if ( get_word(ea) == 0x78E0 ) // nop_s
      return 2;
    if ( get_word(ea) == 0x264A && get_word(ea+2) == 0x7000 ) // mov 0, 0
      return 4;
  }
  return 0;
}

//----------------------------------------------------------------------
static bool can_be_data(ea_t target)
{
  if ( (target & 3) == 0 )
  {
    segment_t *seg = getseg(target);
    if ( seg == NULL )
      return false;
    if ( seg->start_ea == target )
      return true;
    ea_t prev = prev_head(target, seg->start_ea);
    if ( prev != BADADDR && is_data(get_flags(prev)) )
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
// we have a possible reference from current instruction to 'target'
// check if we should make it an offset
static bool good_target(const insn_t &insn, ea_t target)
{
  if ( target <= ' ' )
    return false;

  // check if it points to code
  flags_t F = get_flags(target&~1);
  if ( is_code(F) )
  {
    // arcompact code references should have bit 0 set
    if ( ptype == prc_arcompact && ((target & 1) == 0) )
      return false;

    // arc4 should be word-aligned
    if ( ptype == prc_arc && ((target & 3) != 0) )
      return false;

    if ( !is_head(F) ) // middle of instruction?
      return false;

    // if we're referencing middle of a function, it should be the same function
    func_t *pfn = get_func(target);
    if ( pfn == NULL && is_flow(F) )
      return false;
    if ( pfn != NULL && pfn->start_ea != target && !func_contains(pfn, insn.ea) )
      return false;

    return true;
  }
  else if ( is_data(F) || segtype(target) == SEG_DATA || can_be_data(target) )
  {
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
// returns target address
bool copy_insn_optype(const insn_t &insn, const op_t &x, ea_t ea, void *value, bool force)
{
  flags_t F = get_flags(ea);
  flags_t iflag = get_flags(insn.ea);
  if ( is_dword(F)  && x.dtype == dt_dword
    || is_word(F)   && x.dtype == dt_word
    || is_byte(F)   && x.dtype == dt_byte
    || is_float(F)  && x.dtype == dt_float
    || is_double(F) && x.dtype == dt_double )
  {
    if ( force || is_defarg(F, 0) && is_defarg(iflag, x.n) )
    {
      // both are defined - check that the data types are the same
      // if not, copy insntype -> dwordtype
      flags_t fd = get_optype_flags0(F);
      flags_t fi = get_optype_flags0(x.n ? (iflag>>4) : iflag);
      if ( fd != fi )
      {
        F = (F ^ fd) | fi;
        opinfo_t ti;
        get_opinfo(&ti, insn.ea, x.n, iflag);
        set_opinfo(ea, 0, F, &ti);
        set_op_type(ea, F, 0);
        plan_ea(insn.ea);
        plan_ea(ea);
      }
    }
    if ( x.dtype == dt_dword )
    {
      if ( !is_defarg(F, 0) || (is_off(F, 0) && get_offbase(ea, 0) == to_ea(insn.cs, 0)) )
      {
        uint32 pcval = get_dword(ea);
        ea_t target = to_ea(insn.cs, pcval);
        // if the data is a 32-bit value which can be interpreted as an address
        // then convert it to an offset expression
        if ( get_auto_state() == AU_USED
          // && (inf.af & AF_DATOFF) != 0
          // && target > ' '
          && good_target(insn, target) )
        {
          if ( !is_defarg(F, 0) )
            op_plain_offset(ea, 0, to_ea(insn.cs, 0));
          if ( !is_defarg(get_flags(insn.ea), x.n) )
          {
            op_plain_offset(insn.ea, x.n, to_ea(insn.cs, 0));
          }
        }
        // add xref from "LDR Rx,=addr" to addr.
        if ( is_off(F, 0) )
        {
          // NB: insn_t::add_dref uses insn.ea to calculate the target
          // of a reloc so we can't use it here
          ea_t newto = get_name_base_ea(ea, target);
          dref_t type = dr_O;
          if ( newto != target )
          {
            type = dref_t(type | XREF_TAIL);
            target = newto;
          }
          add_dref(insn.ea, target, type);
          // helper.altdel_ea(ea, DELAY_TAG);
        }
        else
        {
          // analyze later for a possible offset
          // helper.altset_ea(ea, 1, DELAY_TAG);
        }
      }
    }
    if ( value != NULL )
    {
      switch ( x.dtype )
      {
        case dt_dword:
          *(uint32*)value = get_dword(ea);
          break;
        case dt_word:
          *(uint16*)value = get_word(ea);
          break;
        case dt_byte:
          *(uint8*)value = get_byte(ea);
          break;
        case dt_float:
          *(uint32*)value = 0;
          get_bytes(value, 4, ea);
          break;
        case dt_double:
          *(uint64*)value = 0;
          get_bytes(value, 8, ea);
          break;
      }
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Is the current instruction "return"? (conditional or not)
bool is_arc_return_insn(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case ARC_j:
      {
        // j [blink] is a return
        if ( insn.Op1.reg == BLINK )
          return true;
      }
  }
  return false;
}

//--------------------------------------------------------------------------
static const int rv_arc[]  = { R0, R1, R2, R3, R4, R5, R6, R7, -1 };

int get_arc_fastcall_regs(const int **regs)
{
  *regs = rv_arc;
  return qnumber(rv_arc) - 1;
}

//----------------------------------------------------------------------
static void add_argregs(argloc_t *argloc, int r, int nregs, int size, bool force_scattered)
{
  QASSERT(10249, size > (nregs-1) * 4);
  QASSERT(10250, r + nregs < qnumber(rv_arc));
  if ( force_scattered || nregs >= 2 && size != 8 )
  {
    scattered_aloc_t *scloc = new scattered_aloc_t;
    int off = 0;
    for ( int i = 0; i < nregs; ++i, ++r, off += 4 )
    {
      argpart_t &regloc = scloc->push_back();
      regloc.off = off;
      regloc.set_reg1(rv_arc[r]);
      regloc.size = qmin(size, 4);
      size -= 4;
    }
    argloc->consume_scattered(scloc);
  }
  else if ( size == 8 )
  {
    argloc->set_reg2(rv_arc[r], rv_arc[r+1]);
  }
  else
  {
    argloc->set_reg1(rv_arc[r]);
  }
}

//-------------------------------------------------------------------------
bool calc_arc_retloc(argloc_t *retloc, const tinfo_t &tif, cm_t /*cc*/)
{
  if ( !tif.is_void() )
  {
    int size = tif.get_size();
    int nregs = (size + 3) / 4;
    if ( nregs >= qnumber(rv_arc) )
      return false;
    add_argregs(retloc, 0, nregs, size, false);
  }
  debug_print_argloc(-1, *retloc, tif);
  return true;
}

//----------------------------------------------------------------------
// note: currently we do not support partial allocation (when part of
// the argument is in a register and another part is on the stack)
// fixme, but how? we need a means of telling the kernel about partial allocations
static bool alloc_args(func_type_data_t *fti, int nfixed)
{
  if ( !calc_arc_retloc(&fti->retloc, fti->rettype, 0 /*fti->get_cc()*/) )
    return false;

  int r = 0;
  int fr = 0;
  const int NUMREGARGS = 8;

  // if function returns its value in the memory
  size_t retsize = fti->rettype.get_size();
  if ( retsize != BADSIZE && retsize > 8 && !fti->rettype.is_floating() )
    r++; // R0 is used to point to the result

  sval_t spoff = 0;
  for ( int i=0; i < fti->size(); i++ )
  {
    size_t size;
    uint32 align;
    funcarg_t &fa = fti->at(i);
    const tinfo_t &type = fa.type;
    if ( type.empty() && i >= nfixed )
    {
      size = fa.argloc.stkoff();
      align = size;
    }
    else
    {
      size = type.get_size(&align);
    }
    if ( size == BADSIZE )
      return false;
    // XXX: does ARC ABI align 64-bit params? so far doesn't look like it
    if ( size == 8 && align > 4 )
      align = 4;
#ifndef FP_ABI_HARD
    qnotused(fr);
#else
    // currently we support only soft fpu abi
    // todo: add config option to switch between abis
    if ( (size == 4 || size == 8 || size == 16)
      && type.is_floating() )
    {
      // use floating point registers
      int fpr;
      switch ( size )
      {
        case 4:
          fpr = S0 + fr;
          fr++;
          break;
        case 8:
        case 16:              // we do not have Q.. registers yet
          fr = align_up(fr, 2);
          fpr = D0 + fr/2;
          fr += 2;
          break;
      }
      if ( fr > 16 )
        goto ALLOC_ON_STACK;    // no more fpregs
      fa.argloc.set_reg1(fpr);
      debug_print_argloc(i, fa.argloc, fa.type);
      continue;
    }
#endif
    size = align_up(size, 4);
    // XXX: align regs to even pairs?
    /*if ( align > 4 && r < NUMREGARGS )
      r = align_up(r, 2);*/
    if ( r < NUMREGARGS && size <= 16 )
    {
      int nregs = (size+3) / 4;
      int start_reg = r;
      r += nregs;
      if ( nregs == 1 )
      {
        fa.argloc.set_reg1(rv_arc[start_reg]);
      }
      else if ( r <= NUMREGARGS )
      {
        add_argregs(&fa.argloc, start_reg, nregs, size, false);
      }
      else
      { // part of the argument is passed on the stack: mixed scattered
        int nr = NUMREGARGS - start_reg;
        add_argregs(&fa.argloc, start_reg, nr, nr * 4, true);
        scattered_aloc_t &scloc = fa.argloc.scattered();
        argpart_t &stkloc = scloc.push_back();
        stkloc.off = nr * 4;
        stkloc.size = size - stkloc.off;
        stkloc.set_stkoff(0);
        spoff += align_up(stkloc.size, 4);
      }
    }
    else
    {
// ALLOC_ON_STACK:
      if ( align > 4 )
        spoff = align_up(spoff, 8);
      fa.argloc.set_stkoff(spoff);
      spoff += size;
    }
    debug_print_argloc(i, fa.argloc, fa.type);
  }
  fti->stkargs = spoff;
  return true;
}

//----------------------------------------------------------------------
bool calc_arc_arglocs(func_type_data_t *fti)
{
  return alloc_args(fti, fti->size());
}

//-------------------------------------------------------------------------
bool calc_arc_varglocs(
        func_type_data_t *fti,
        regobjs_t * /*regargs*/,
        int nfixed)
{
  return alloc_args(fti, nfixed);
}

//-------------------------------------------------------------------------
// returns:
//      -1: doesn't spoil anything
//      -2: spoils everything
//     >=0: the number of the spoiled register
static int spoils(const insn_t &insn, const uint32 *regs, int n)
{
  if ( is_call_insn(insn) )
    return -2;

  for ( int i=0; i < n; i++ )
    if ( spoils(insn, regs[i]) )
      return i;

  return -1;
}

//-------------------------------------------------------------------------
static bool arc_set_op_type(const insn_t &insn, const op_t &x, const tinfo_t &tif, const char *name, eavec_t &visited)
{
  tinfo_t type = tif;
  switch ( x.type )
  {
    case o_imm:
      if ( type.is_ptr()
        && x.value != 0
        && !is_defarg(get_flags(insn.ea), x.n) )
      {
        op_plain_offset(insn.ea, x.n, to_ea(insn.cs, 0));
        return true;
      }
      break;
    case o_mem:
      {
        ea_t dea = to_ea(insn.cs, x.addr);
        return apply_once_tinfo_and_name(dea, type, name);
      }
    case o_displ:
      return apply_tinfo_to_stkarg(insn, x, x.addr, type, name);
    case o_reg:
      {
        uint32 r = x.reg;
        func_t *pfn = get_func(insn.ea);
        if ( pfn == NULL )
          return false;
        bool ok;
        bool farref;
        func_item_iterator_t fii;
        insn_t insn1;
        for ( ok=fii.set(pfn, insn.ea);
              ok && (ok=fii.decode_preceding_insn(&visited, &farref, &insn1)) != false;
              )
        {
          if ( visited.size() > 4096 )
            break; // decoded enough of it, abandon
          if ( farref )
            continue;
          switch ( insn1.itype )
          {
            case ARC_mov:
            case ARC_ld:
              if ( insn1.Op1.reg != r )
                continue;
              return arc_set_op_type(insn, insn1.Op2, type, name, visited);
            case ARC_add:
            case ARC_sub:
              // SUB       R3, R11, #-var_12C
              // ADD       R1, SP, #var_1C
              if ( insn1.Op1.reg != r )
                continue;
              if ( (issp(insn1.Op2) /*|| isfp(insn1.Op2)*/ )
                && insn1.Op3.type != o_void )
                {
                  if ( remove_tinfo_pointer(&type, &name) )
                    return apply_tinfo_to_stkarg(insn, insn1.Op3, insn1.Op3.value, type, name);
                }
              // no break
            default:
              {
                int code = spoils(insn, &r, 1);
                if ( code == -1 )
                  continue;
              }
              break;
          }
          break;
        }
      }
      break;
  }
  return false;
}

//-------------------------------------------------------------------------
static bool idaapi set_op_type(const insn_t &insn, const op_t &x, const tinfo_t &type, const char *name)
{
  eavec_t visited;
  return arc_set_op_type(insn, x, type, name, visited);
}

//-------------------------------------------------------------------------
int use_arc_regarg_type(ea_t ea, const funcargvec_t &rargs)
{
  int idx = -1;
  insn_t insn;
  if ( decode_insn(&insn, ea) )
  {
    qvector<uint32> regs;
    int n = rargs.size();
    regs.resize(n);
    for ( int i=0; i < n; i++ )
      regs[i] = rargs[i].argloc.reg1();

    idx = spoils(insn, regs.begin(), n);
    if ( idx >= 0 )
    {
      tinfo_t type = rargs[idx].type;
      const char *name = rargs[idx].name.begin();
      switch ( insn.itype )
      {

        case ARC_add:   // add     r1, sp, #stkvar
        case ARC_sub:   // sub     r1, r11, #0x15C
          if ( (issp(insn.Op2) /*|| isfp(insn.Op2)*/)
            && insn.Op3.type != o_void )
            if ( remove_tinfo_pointer(&type, &name) )
              apply_tinfo_to_stkarg(insn, insn.Op3, insn.Op3.value, type, name);
          break;
        case ARC_mov:
        case ARC_ld:
          set_op_type(insn, insn.Op2, type, name);
          break;
        default: // unknown instruction changed the register, stop tracing it
          idx |= REG_SPOIL;
          break;
      }
    }
  }
  return idx;
}

//-------------------------------------------------------------------------
static bool idaapi is_stkarg_load(const insn_t &insn, int *src, int *dst)
{
  if ( insn.itype == ARC_st && is_sp_based(insn, insn.Op2) )
  {
    *src = 0;
    *dst = 1;
    return true;
  }
  return false;
}

//-------------------------------------------------------------------------
void use_arc_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs)
{
  gen_use_arg_tinfos(ea, fti, rargs,
                     set_op_type,
                     is_stkarg_load,
                     NULL);
}

//----------------------------------------------------------------------
// does the current instruction end a basic block?
bool is_arc_basic_block_end(const insn_t &insn)
{
  // is this a delay slot of a branch?
  if ( is_dslot(insn.ea, false) )
    return true;

  // do we flow into next instruction?
  if ( !is_flow(get_flags(insn.ea+insn.size)) )
    return true;

  // are there jump xrefs from here?
  xrefblk_t xb;
  bool has_jumps = false;
  for ( bool ok=xb.first_from(insn.ea, XREF_FAR); ok && xb.iscode; ok=xb.next_from() )
  {
    if ( xb.type == fl_JF || xb.type == fl_JN )
    {
      has_jumps = true;
      break;
    }
  }

  if ( has_jumps )
  {
    // delayed jump does not end a basic block
    return !has_dslot(insn);
  }
  return false;
}

//----------------------------------------------------------------------
void del_insn_info(ea_t ea)
{
  // delete delay slot info
  // NB: may not clobber cmd here!
  nodeidx_t ndx = ea2node(ea);
  helper.altdel(ndx, DSLOT_TAG);
  if ( is_code(get_flags(ea)) )
    helper.altdel(ndx + get_item_size(ea), DSLOT_TAG);
  del_callee(ea);
  del_dxref(ea);
}
