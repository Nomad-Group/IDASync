/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor emulator
 *
 */
#include <ida.hpp>
#include <auto.hpp>
#include <frame.hpp>
#include "ins.hpp"
#include "necv850.hpp"

//----------------------------------------------------------------------
//#notify.is_sane_insn
// is the instruction sane for the current file type?
// arg:  int no_crefs
// 1: the instruction has no code refs to it.
//    ida just tries to convert unexplored bytes
//    to an instruction (but there is no other
//    reason to convert them into an instruction)
// 0: the instruction is created because
//    of some coderef, user request or another
//    weighty reason.
// The instruction is in 'cmd'
// returns: 1-ok, <=0-no, the instruction isn't likely to appear in the program
int nec850_is_sane_insn(const insn_t &insn, int /*no_crefs*/)
{
#define CHECK_R0_WRITE(n) \
  if ( ((Feature & CF_CHG ## n) != 0)  \
    && insn.Op ## n.is_reg(rZERO) )  \
  { \
      return 0; \
  }
  int Feature = insn.get_canon_feature();

  CHECK_R0_WRITE(1);
  CHECK_R0_WRITE(2);
  return 1;
}

//----------------------------------------------------------------------
// return number of set bits
static int bitcount(uint32 w)
{
  uint32 allones = ~0;
  uint32 mask1h = (allones / 3) << 1;
  uint32 mask2l = allones / 5;
  uint32 mask4l = allones / 17;
  w -= (mask1h & w) >> 1;
  w = (w & mask2l) + ((w>>2) & mask2l);
  w = (w + (w >> 4)) & mask4l;
  w += w >> 8;
  w += w >> 16;
  return w & 0xff;
}

//----------------------------------------------------------------------
int idaapi nec850_is_sp_based(const insn_t &insn, const op_t &x)
{
  int res = OP_SP_ADD;
  if ( x.type == o_displ && x.reg == rSP )
    return res | OP_SP_BASED;

  // check for movea   8, sp, r28
  if ( insn.itype == NEC850_MOVEA && insn.Op2.is_reg(rSP) && x.type == o_imm )
    return res | OP_SP_BASED;

  return res | OP_FP_BASED;
}

//----------------------------------------------------------------------
bool idaapi nec850_create_func_frame(func_t *pfn)
{
  asize_t frsize;

  insn_t insn;
  if ( decode_insn(&insn, pfn->start_ea) != 0
    && (insn.itype == NEC850_PREPARE_i || insn.itype == NEC850_PREPARE_sp) )
  {
    frsize = insn.Op2.value * 4;
  }
  else
  {
    frsize = 0;
  }
  return add_frame(pfn, frsize, 0, 0);
}

//----------------------------------------------------------------------
int idaapi nec850_get_frame_retsize(const func_t * /*pfn*/)
{
  return 0;
}

//----------------------------------------------------------------------
static bool spoils(const insn_t &insn, uint16 reg)
{
  int n;
  switch ( reg )
  {
    case NEC850_ZXB:
    case NEC850_SXB:
    case NEC850_ZXH:
    case NEC850_SXH:
      n = 0;
      break;

    case NEC850_XOR:
    case NEC850_SUBR:
    case NEC850_SUB:
    case NEC850_STSR:
    case NEC850_SLD_B:
    case NEC850_SLD_H:
    case NEC850_SLD_W:
    case NEC850_SHR:
    case NEC850_SHL:
    case NEC850_SETFV:
    case NEC850_SETFL:
    case NEC850_SETFZ:
    case NEC850_SETFNH:
    case NEC850_SETFN:
    case NEC850_SETFT:
    case NEC850_SETFLT:
    case NEC850_SETFLE:
    case NEC850_SETFNV:
    case NEC850_SETFNC:
    case NEC850_SETFNZ:
    case NEC850_SETFH:
    case NEC850_SETFP:
    case NEC850_SETFSA:
    case NEC850_SETFGE:
    case NEC850_SETFGT:
    case NEC850_SATSUBR:
    case NEC850_SATSUB:
    case NEC850_SATADD:
    case NEC850_SAR:
    case NEC850_OR:
    case NEC850_NOT:
    case NEC850_MULH:
    case NEC850_MOV:
    case NEC850_LD_B:
    case NEC850_LD_H:
    case NEC850_LD_W:
    case NEC850_JARL:
    case NEC850_AND:
    case NEC850_ADD:
    case NEC850_SASFV:
    case NEC850_SASFL:
    case NEC850_SASFZ:
    case NEC850_SASFNH:
    case NEC850_SASFN:
    case NEC850_SASFT:
    case NEC850_SASFLT:
    case NEC850_SASFLE:
    case NEC850_SASFNV:
    case NEC850_SASFNC:
    case NEC850_SASFNZ:
    case NEC850_SASFH:
    case NEC850_SASFP:
    case NEC850_SASFSA:
    case NEC850_SASFGE:
    case NEC850_SASFGT:
    case NEC850_DIVH:
    case NEC850_BSW:
    case NEC850_BSH:
    case NEC850_HSW:
    case NEC850_SLD_BU:
    case NEC850_SLD_HU:
    case NEC850_LD_BU:
    case NEC850_LD_HU:
      n = 1;
      break;

    case NEC850_XORI:
    case NEC850_SATSUBI:
    case NEC850_ORI:
    case NEC850_MULHI:
    case NEC850_MOVHI:
    case NEC850_MOVEA:
    case NEC850_ANDI:
    case NEC850_ADDI:
      n = 2;
      break;

    case NEC850_CMOVV:
    case NEC850_CMOVL:
    case NEC850_CMOVZ:
    case NEC850_CMOVNH:
    case NEC850_CMOVN:
    case NEC850_CMOV:
    case NEC850_CMOVLT:
    case NEC850_CMOVLE:
    case NEC850_CMOVNV:
    case NEC850_CMOVNC:
    case NEC850_CMOVNZ:
    case NEC850_CMOVH:
    case NEC850_CMOVP:
    case NEC850_CMOVSA:
    case NEC850_CMOVGE:
    case NEC850_CMOVGT:
      n = 3;
      break;

    case NEC850_MUL:
    case NEC850_MULU:
    case NEC850_DIVH_r3:
    case NEC850_DIVHU:
    case NEC850_DIV:
    case NEC850_DIVU:
      return insn.ops[1].is_reg(reg) || insn.ops[2].is_reg(reg);

    case NEC850_DISPOSE_r0:
    case NEC850_DISPOSE_r:
      return reg == rSP || reg_in_list12(reg, insn.Op2.value);

    case NEC850_PREPARE_sp:
      return reg == rSP;

    case NEC850_PREPARE_i:
      return reg == rSP || reg == rEP;

    default:
      return false;
  }
  return insn.ops[n].is_reg(reg);
}

//----------------------------------------------------------------------
static bool get_gp_based_addr(ea_t *target, const insn_t &_insn, const op_t &op)
{
  if ( g_gp_ea == BADADDR )
    return false;
  if ( op.phrase == rGP )
  {
    *target = g_gp_ea;
    return true;
  }
  uint16 op_phrase = op.phrase;
  *target = BADADDR;
  insn_t tmp = _insn;
  while ( true )
  {
    flags_t F = get_flags(tmp.ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
    if ( decode_prev_insn(&tmp, tmp.ea) == BADADDR )
      break;

    if ( tmp.itype == NEC850_MOVEA
      && tmp.Op2.reg == rGP
      && tmp.Op3.reg == op_phrase )
    {
      *target = g_gp_ea + tmp.Op1.value;
      break;
    }

    if ( spoils(tmp, op_phrase) )
      break;
  }
  return *target != BADADDR;
}

//----------------------------------------------------------------------
static void handle_operand(const insn_t &insn, const op_t &op, bool isRead)
{
  ea_t ea;
  flags_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    case o_imm:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, 0);
      break;

    case o_displ:
      set_immd(insn.ea);
      if ( !is_defarg(F, op.n) )
      {
        if ( may_create_stkvars() && op.reg == rSP )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != NULL && insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, op.n);
        }
        else if ( get_gp_based_addr(&ea, insn, op) )
        {
          refinfo_t ri;
          ri.flags = REF_OFF32|REFINFO_PASTEND|REFINFO_NOBASE|REFINFO_SIGNEDOP;
          ri.target = BADADDR;
          ri.base = ea;
          ri.tdelta = 0;
          op_offset_ex(insn.ea, op.n, &ri);
          F = get_flags(insn.ea);
        }
      }

      if ( op_adds_xrefs(F, op.n) )
      { // create data xrefs
        ea_t base_ea;
        if ( get_gp_based_addr(&base_ea, insn, op) )
        {
          ea = base_ea + op.addr;
          insn.add_dref(ea, op.offb, isRead ? dr_R : dr_W);
        }
        else
        {
          int outf = OOF_ADDR | OOFW_16;
          if ( (op.specflag1 & N850F_OUTSIGNED) != 0 )
            outf |= OOFS_IFSIGN | OOF_SIGNED;
          ea = insn.add_off_drefs(op, isRead ? dr_R : dr_W, outf);
        }
        if ( ea != BADADDR )
          insn.create_op_data(ea, op);
      }
      break;

    case o_mem:
      {
        ea = to_ea(insn.cs, op.addr);
        insn.create_op_data(ea, op);
        insn.add_dref(op.addr, op.offb, isRead ? dr_R : dr_W);
      }
      break;
  }
}

//----------------------------------------------------------------------
static void idaapi trace_stack(func_t *pfn, const insn_t &insn)
{
  sval_t delta;
  switch ( insn.itype )
  {
  case NEC850_PREPARE_i:
  case NEC850_PREPARE_sp:
    {
      delta = -((bitcount(insn.Op1.value) * 4) + (insn.Op2.value << 2));

      // PATTERN #1
      /*
      00000030     _func3:
      00000030 000                 br      loc_5E
      00000032
      00000032     loc_32:                                 -- CODE XREF: _func3+32j
      00000032 000                 st.w    r6, 4[sp]
      0000005A
      0000005A     loc_5A:                                 -- CODE XREF: _func3+10j
      0000005A                                             -- _func3+14j ...
      0000005A 000                 dispose 2, {lp}, [lp]
      0000005E     -- ---------------------------------------------------------------------------
      0000005E
      0000005E     loc_5E:                                 -- CODE XREF: _func3
      0000005E -0C                 prepare {lp}, 2
      00000062 000                 br      loc_32
      00000062     -- End of function _func3
      */
      bool farref;
      insn_t tmp;
      if ( decode_preceding_insn(&tmp, insn.ea, &farref) != BADADDR
        && (tmp.itype == NEC850_BR || tmp.itype == NEC850_JR)
        && tmp.Op1.addr == insn.ea
        && func_contains(pfn, tmp.ea) )
      {
        add_auto_stkpnt(pfn, tmp.ea + tmp.size, delta);
      }
    }
    break;
  case NEC850_DISPOSE_r:
  case NEC850_DISPOSE_r0:
    // count registers in LIST12 and use the imm5 for local vars
    delta = (bitcount(insn.Op2.value) * 4) + (insn.Op1.value << 2);
    break;
  case NEC850_ADD:
  case NEC850_ADDI:
  case NEC850_MOVEA:
    delta = insn.Op1.value;
    break;
  default:
    return;
  }
  add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

//----------------------------------------------------------------------
// pattern:
//   mov #address, lp
//   jmp [reg1]
// returns:
//   flow to the next instruction
static bool indirect_function_call(const insn_t &_insn)
{
  if ( _insn.itype != NEC850_JMP || _insn.Op1.is_reg(rLP) )
    return false;

  insn_t insn = _insn;
  ea_t ret_addr = insn.ea + 2;   // JMP [reg1] - two bytes long

  bool flow = false;
  while ( decode_prev_insn(&insn, insn.ea) != BADADDR )
  {
    if ( insn.itype == NEC850_MOV
      && insn.Op1.type == o_imm
      && insn.Op1.dtype == dt_dword
      && insn.Op2.is_reg(rLP) )
    { // MOV #address, lp
      op_offset(insn.ea, 0, REF_OFF32);
      if ( insn.Op1.value == ret_addr )
      { // normal return, after the call instruction
        flow = true;
      }
      else
      { // add xref to return address
        add_cref(_insn.ea, insn.Op1.value, fl_JN);
      }
      break;
    }

    if ( spoils(insn, rLP) )
      break;

    flags_t F = get_flags(insn.ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
  }
  return flow;
}

//----------------------------------------------------------------------
int idaapi nec850_emu(const insn_t &insn)
{
  int aux = insn.auxpref;
  const op_t *op = aux & N850F_ADDR_OP1
                 ? &insn.Op1
                 : aux & N850F_ADDR_OP2
                 ? &insn.Op2
                 : NULL;

  int Feature = insn.get_canon_feature();

  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_USE3 )
    handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_CHG3 )
    handle_operand(insn, insn.Op3, false);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  flags_t F = get_flags(insn.ea);
  if ( insn.itype == NEC850_MOVEA
    && insn.Op1.type == o_imm
    && !is_defarg(F, insn.Op1.n) )
  {
    if ( insn.Op2.is_reg(rSP)
      && may_create_stkvars()
      && insn.create_stkvar(insn.Op1, insn.Op1.value, 0) )
    {
      op_stkvar(insn.ea, insn.Op1.n);
    }
    else if ( insn.Op2.is_reg(rGP)
           && g_gp_ea != BADADDR )
    {
      ea_t ea = g_gp_ea + insn.Op1.value;

      refinfo_t ri;
      ri.flags = REF_OFF32|REFINFO_PASTEND|REFINFO_SIGNEDOP|REFINFO_NOBASE;
      ri.target = BADADDR;
      ri.base = g_gp_ea;
      ri.tdelta = 0;
      op_offset_ex(insn.ea, insn.Op1.n, &ri);
      F = get_flags(insn.ea);
      if ( op_adds_xrefs(F, insn.Op1.n) )
        insn.add_dref(ea, insn.Op1.offb, dr_O);
    }
  }

  // add dref to callt table entry address
  if ( insn.itype == NEC850_CALLT
    && g_ctbp_ea != BADADDR )
  {
    ea_t ea = g_ctbp_ea + (insn.Op1.value << 1);
    insn.create_op_data(ea, insn.Op1.offb, dt_word);
    insn.add_dref(ea, insn.Op1.offb, dr_R);
  }

  // add jump or call ( type = o_near )
  if ( op != NULL )
  {
    cref_t ftype = fl_JN;
    if ( (aux & N850F_CALL) != 0 )
    {
      if ( !func_does_return(op->addr) )
        Feature |= CF_STOP;
      ftype = fl_CN;
    }
    insn.add_cref(op->addr, op->offb, ftype);
  }

  if ( indirect_function_call(insn) )
    Feature &= ~CF_STOP;

  if ( (aux & N850F_SP) && may_trace_sp() )
  {
    func_t *pfn = get_func(insn.ea);
    if ( pfn != NULL )
      trace_stack(pfn, insn);
  }

  // add flow
  if ( (Feature & CF_STOP) == 0 )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int nec850_may_be_func(const insn_t &insn)
{
  int prop = 0;
  if ( insn.itype == NEC850_PREPARE_i || insn.itype == NEC850_PREPARE_sp )
    prop = 100;
  return prop;
}

//----------------------------------------------------------------------
inline bool is_ret_itype(const insn_t &insn)
{
  return insn.itype == NEC850_RETI
      || insn.itype == NEC850_DBRET
      || insn.itype == NEC850_CTRET
      || insn.itype == NEC850_DISPOSE_r
      || insn.itype == NEC850_JMP && insn.Op1.is_reg(rLP);
}

//----------------------------------------------------------------------
bool nec850_is_return(const insn_t &insn, bool strict)
{
  if ( is_ret_itype(insn) )
    return true;
  if ( insn.itype == NEC850_DISPOSE_r0 )
    return !strict;
  return false;
}

//----------------------------------------------------------------------
#include "../jptcmn.cpp"

//======================================================================
// Jump patterns parent
//  0  switch  rSW

class nec850_jmp_pattern_t : public jump_pattern_t
{
protected:
  enum { rSW = 1, rREG };
  bool is_cmp_reg;

  nec850_jmp_pattern_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : jump_pattern_t(_si, _roots, _depends)
  {
    allow_noflows = false;
    allow_farrefs = false;
    is_cmp_reg = false;
  }

  uint16 get_moved_reg(int r_i) const
  {
    return !spoiled[r_i] ? r[r_i] : r_moved[r_i].reg;
  }

  bool jpi_cmp(void);
  // check for lowcase, it must be near above the current insn
  void check_for_lowcase(void);

public:
  virtual bool jpi0(void);
  virtual bool handle_mov(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern_t::handle_mov(void)
{
  if ( insn.itype == NEC850_MOV
    && insn.Op1.type == o_reg
    && insn.Op2.type == o_reg )
  {
    bool ok = mov_set(insn.Op2.reg, insn.Op1);
    return ok;
  }
  return false;
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern_t::jpi_cmp(void)
{
  bool ok = insn.itype == NEC850_CMP
         && is_same(insn.Op2, rSW);
  if ( ok )
  {
    if ( insn.Op1.type == o_imm )
    {
      si->ncases = insn.Op1.value + 1;
    }
    else
    {
      is_cmp_reg = true;
      r[rREG] = insn.Op1.reg;
      spoiled[rREG] = false;
    }
  }
  return ok;
}

//----------------------------------------------------------------------
void nec850_jmp_pattern_t::check_for_lowcase(void)
{
  insn_t tmp = insn;
  for ( int i=0; i < 5; ++i )
  {
    if ( decode_prev_insn(&tmp, tmp.ea) == BADADDR )
      break;
    if ( tmp.itype == NEC850_MOVEA && is_same(tmp.Op3, rSW)
      || tmp.itype == NEC850_ADD && tmp.Op1.type == o_imm && is_same(tmp.Op2, rSW) )
    {
      si->lowcase = uval_t(-uint32(tmp.Op1.value));
      break;
    }

    if ( spoils(tmp, get_moved_reg(rSW)) )
      break;
    flags_t F = get_flags(tmp.ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
  }
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern_t::jpi0(void)
{
  bool ok = insn.itype == NEC850_SWITCH
         && insn.Op1.reg != rZERO;

  if ( ok )
  {
    si->startea = insn.ea;
    si->jumps = insn.ea + insn.size;
    si->elbase = si->jumps;
    si->set_jtable_element_size(2);

    si->set_expr(insn.Op1.reg, dt_dword);
    r[rSW] = insn.Op1.reg;

    si->flags |= SWI_DEFAULT | SWI_ELBASE | SWI_SIGNED;
    si->set_shift(1);
  }
  return ok;
}

//======================================================================
// 'bh' based pattern:
//  2  cmp     si->ncases, rSW
//  2  cmp     reg, rSW
//  1  bh      si->default
//  0  switch  rSW

static const char roots_nec850_jmp[] = { 1, 0 };

class nec850_jmp_pattern_bh_based_t : public nec850_jmp_pattern_t
{
protected:
  nec850_jmp_pattern_bh_based_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : nec850_jmp_pattern_t(_si, _roots, _depends)
  {
  }

public:
  virtual bool jpi2(void);
  virtual bool jpi1(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bh_based_t::jpi2(void)
{
  return jpi_cmp();
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bh_based_t::jpi1(void)
{
  bool ok = insn.itype == NEC850_BH;
  if ( ok )
    si->defjump = insn.Op1.addr;
  return ok;
}

//======================================================================
// 'bnh; jr' based pattern:
//  3  cmp     si->ncases, rSW
//  3  cmp     reg, rSW
//  2  bnh     loc
//  1  jr      si->default
//  loc:
//  0  switch  rSW

class nec850_jmp_pattern_bnh_jr_based_t : public nec850_jmp_pattern_t
{
protected:

  nec850_jmp_pattern_bnh_jr_based_t(switch_info_t *_si, const char *_roots, const char (*_depends)[2])
    : nec850_jmp_pattern_t(_si, _roots, _depends)
  {
    allow_noflows = true;
  }

public:
  virtual bool jpi3(void);
  virtual bool jpi2(void);
  virtual bool jpi1(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bnh_jr_based_t::jpi3(void)
{
  return jpi_cmp();
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bnh_jr_based_t::jpi2(void)
{
  bool ok = insn.itype == NEC850_BNH
         && insn.Op1.addr == si->startea;
  return ok;
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bnh_jr_based_t::jpi1(void)
{
  bool ok = insn.itype == NEC850_JR;
  if ( ok )
    si->defjump = insn.Op1.addr;
  return ok;
}

//======================================================================
//     movea   -si->lowcase, reg, rSW || add     -si->lowcase, rSW
//  2  cmp     si->ncases, rSW
//  1  bh      si->default
//  0  switch  rSW

static const char depends_nec850_jmp0[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 0 },    // 2
};

class nec850_jmp_pattern0_t : public nec850_jmp_pattern_bh_based_t
{
public:
  nec850_jmp_pattern0_t(switch_info_t *_si)
    : nec850_jmp_pattern_bh_based_t(_si, roots_nec850_jmp, depends_nec850_jmp0)
  {
  }

  virtual bool jpi2(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern0_t::jpi2(void)
{
  if ( !nec850_jmp_pattern_bh_based_t::jpi2()
    || is_cmp_reg )
  {
    return false;
  }

  check_for_lowcase();
  return true;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern0(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern0_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
// 3 movea   si->ncases, r0, rREG
// 2 cmp     rREG, rSW
// 1 bh      si->default
// 0 switch  rSW

static const char depends_nec850_jmp1[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 3 },    // 2
  { 0 },    // 3
};

class nec850_jmp_pattern1_t : public nec850_jmp_pattern_bh_based_t
{
public:
  nec850_jmp_pattern1_t(switch_info_t *_si)
    : nec850_jmp_pattern_bh_based_t(_si, roots_nec850_jmp, depends_nec850_jmp1)
  {
  }

  virtual bool jpi3(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern1_t::jpi3(void)
{
  bool ok = is_cmp_reg
         && insn.itype == NEC850_MOVEA
         && insn.Op2.is_reg(rZERO)
         && is_same(insn.Op3, rREG);
  if ( ok )
    si->ncases = insn.Op1.value + 1;
  return ok;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern1(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern1_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
// The last attempt: assume switch with 1 element
// 2 cmp     rREG, rSW
// 1 bh      si->default
// 0 switch  rSW
static const char depends_nec850_jmp2[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 0 },    // 2
};

class nec850_jmp_pattern_bh_last_t : public nec850_jmp_pattern_bh_based_t
{
public:
  nec850_jmp_pattern_bh_last_t(switch_info_t *_si)
    : nec850_jmp_pattern_bh_based_t(_si, roots_nec850_jmp, depends_nec850_jmp2)
  {
  }

  virtual bool jpi2(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern_bh_last_t::jpi2(void)
{
  if ( !nec850_jmp_pattern_bh_based_t::jpi2()
    || !is_cmp_reg )
  {
    return false;
  }

  si->ncases = 1;
  return true;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern_bh_last(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern_bh_last_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
//  4  movea   si->ncases, r0, rREG
//  3  cmp     reg, rSW
//  2  bnh     loc
//  1  jr      si->default
//  loc:
//  0  switch  rSW

static const char depends_nec850_jmp3[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 3 },    // 2
  { 4 },    // 3
  { 0 },    // 4
};

class nec850_jmp_pattern3_t : public nec850_jmp_pattern_bnh_jr_based_t
{
public:
  nec850_jmp_pattern3_t(switch_info_t *_si)
    : nec850_jmp_pattern_bnh_jr_based_t(_si, roots_nec850_jmp, depends_nec850_jmp3)
  {
  }

  virtual bool jpi4(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern3_t::jpi4(void)
{
  bool ok = is_cmp_reg
         && insn.itype == NEC850_MOVEA
         && insn.Op2.is_reg(rZERO)
         && is_same(insn.Op3, rREG);
  if ( ok )
    si->ncases = insn.Op1.value + 1;
  return ok;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern3(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern3_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
//     movea   -si->lowcase, reg, rSW || add     -si->lowcase, rSW
//  3  cmp     si->ncases, rSW
//  2  bnh     loc
//  1  jr      si->default
//  loc:
//  0  switch  rSW

static const char depends_nec850_jmp4[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 3 },    // 2
  { 0 },    // 3
};

class nec850_jmp_pattern4_t : public nec850_jmp_pattern_bnh_jr_based_t
{
public:
  nec850_jmp_pattern4_t(switch_info_t *_si)
    : nec850_jmp_pattern_bnh_jr_based_t(_si, roots_nec850_jmp, depends_nec850_jmp4)
  {
  }

  virtual bool jpi3(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern4_t::jpi3(void)
{
  if ( !jpi_cmp() || is_cmp_reg )
    return false;

  check_for_lowcase();
  return true;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern4(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern4_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
//  2  addi   si->ncases, rSW, r0
//  1  bl     si->default
//  0  switch rSW

static const char depends_nec850_jmp5[][2] =
{
  { 1 },    // 0
  { 2 },    // 1
  { 0 },    // 2
};

class nec850_jmp_pattern5_t : public nec850_jmp_pattern_t
{
public:
  nec850_jmp_pattern5_t(switch_info_t *_si)
    : nec850_jmp_pattern_t(_si, roots_nec850_jmp, depends_nec850_jmp5)
  {
  }

  virtual bool jpi2(void);
  virtual bool jpi1(void);
};

//----------------------------------------------------------------------
bool nec850_jmp_pattern5_t::jpi2(void)
{
  bool ok = insn.itype == NEC850_ADDI
         && insn.Op1.type == o_imm
         && is_same(insn.Op2, rSW)
         && insn.Op3.reg == rZERO;
  if ( ok )
    si->ncases = uval_t(-uint32(insn.Op1.value));
  return ok;
}

//----------------------------------------------------------------------
bool nec850_jmp_pattern5_t::jpi1(void)
{
  bool ok = insn.itype == NEC850_BL;
  if ( ok )
    si->defjump = insn.Op1.addr;
  return ok;
}

//----------------------------------------------------------------------
static jump_table_type_t is_nec850_pattern5(switch_info_t *si, const insn_t &insn)
{
  nec850_jmp_pattern5_t jp(si);
  return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

//======================================================================
static bool check_for_jumps(switch_info_t *si, const insn_t &insn)
{
  static is_pattern_t *const patterns[] =
  {
    is_nec850_pattern0,
    is_nec850_pattern1,
    is_nec850_pattern_bh_last,
    is_nec850_pattern3,
    is_nec850_pattern4,
    is_nec850_pattern5,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns));
}

//----------------------------------------------------------------------
bool idaapi nec850_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype != NEC850_SWITCH )
    return false;

  return check_for_jumps(si, insn);
}
