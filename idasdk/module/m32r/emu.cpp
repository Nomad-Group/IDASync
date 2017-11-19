
#include "m32r.hpp"

static bool flow;

// handle immediate values
static void handle_imm(void) {

    doImmd(cmd.ea);
}

//----------------------------------------------------------------------
// handle the custom switch format
//     ....
//     bl.s next || nop  <- insn_ea
//  next:
//     add  lr, R0
//     jmp  lr
// si.jumps:
//     bra.s case0 || nop
//     bra.l case1
//     ...
int m32r_create_switch_xrefs(ea_t insn_ea, const switch_info_ex_t &si)
{
  if ( (si.flags & SWI_CUSTOM) != 0 )
  {
    insn_t saved = cmd;
    decode_insn(insn_ea);
    ea_t ea = si.jumps;
    for ( int i = 0; i < si.ncases; i++, ea += cmd.size )
    {
      add_cref(insn_ea, ea, fl_JN);
      decode_insn(ea);
      if ( cmd.Op1.type == o_near )
      {
        ea_t target = toEA(cmd.cs, cmd.Op1.addr);
        // xrefs are from "bl" -> branch target.
        add_cref(insn_ea, target, fl_JN);
      }
    }
    cmd = saved;
  }
  return 2; // ok
}

//----------------------------------------------------------------------
int m32r_calc_switch_cases(ea_t /*insn_ea*/, const switch_info_ex_t *si, casevec_t *casevec, eavec_t *targets)
{
  if ( si == NULL || (si->flags & SWI_CUSTOM) == 0 )
    return 1;

  insn_t saved = cmd;
  ea_t ea = si->jumps;
  svalvec_t vals;
  vals.push_back(0); //add one item
  for ( int i=0; i < si->ncases; i++, ea += cmd.size )
  {
    decode_insn(ea);
    if ( targets != NULL )
    {
      if ( cmd.itype == m32r_bra && cmd.Op1.type == o_near )
        targets->push_back(cmd.Op1.addr);
      else
        targets->push_back(cmd.ea);
    }
    if ( casevec != NULL )
    {
      vals[0] = i;
      casevec->push_back(vals);
    }
  }
  cmd = saved;
  return 2; // ok
}

//----------------------------------------------------------------------
static bool handle_switch(void)
{
  switch_info_ex_t si;
  bool ok = (uFlag & FF_JUMP) != 0
         && get_switch_info_ex(cmd.ea, &si, sizeof(si)) > 0;

  if ( !ok )
  {
    //  ldi8    R1, #0x21 ; '!'
    //  cmpu    R1, R0
    //  bc.l    loc_67F8C
    //  slli    R0, #2
    //  addi    R0, #4
    //  bl.s    next || nop
    // next:
    //  add     lr, R0
    //  jmp     lr
    //  bra.s   loc_67CDC || nop
    //  bra.s   loc_67D34 || nop
    //  bra.l   loc_67F8C
    //  ...
    if ( cmd.itype != m32r_bl )
      return false;

    // bl should be to next address
    ea_t tgt = toEA(cmd.cs, cmd.Op1.addr);
    if ( tgt != cmd.ea + cmd.size )
      return false;

    insn_t saved = cmd;

    // check for add lr, R0; jmp lr
    if ( decode_insn(tgt) == 0
      || cmd.itype != m32r_add
      || !cmd.Op1.is_reg(rLR)
      || cmd.Op2.type != o_reg )
    {
  BAD_MATCH:
      cmd = saved;
      return false;
    }

    int switch_reg = cmd.Op2.reg;

    // jmp lr
    if ( decode_insn(cmd.ea + cmd.size) == 0
      || cmd.itype != m32r_jmp
      || !cmd.Op1.is_reg(rLR) )
    {
      goto BAD_MATCH;
    }

    // addi    R0, #4
    if ( decode_prev_insn(saved.ea) == BADADDR
      || cmd.itype != m32r_addi
      || !cmd.Op1.is_reg(switch_reg)
      || cmd.Op2.type != o_imm )
    {
      goto BAD_MATCH;
    }

    ea_t jumps = saved.ea + saved.size + cmd.Op2.value;

    // slli    R0, #2
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != m32r_slli
      || !cmd.Op1.is_reg(switch_reg)
      || !cmd.Op2.is_imm(2) )
    {
      goto BAD_MATCH;
    }

    // bc.l    default
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != m32r_bc )
    {
      goto BAD_MATCH;
    }

    ea_t defea = toEA(cmd.cs, cmd.Op1.addr);

    // cmpu    R1, R0
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != m32r_cmpu
      || !cmd.Op2.is_reg(switch_reg)
      || cmd.Op1.type != o_reg )
    {
      goto BAD_MATCH;
    }

    int cmpreg = cmd.Op1.reg;

    // ldi8    R1, #max
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != m32r_ldi
      || !cmd.Op1.is_reg(cmpreg)
      || cmd.Op2.type != o_imm )
    {
      goto BAD_MATCH;
    }

    // looks good

    si.flags  |= SWI_DEFAULT|SWI_CUSTOM|SWI_J32;
    si.ncases  = cmd.Op2.value + 1;
    si.jumps   = jumps;
    si.lowcase = 0;
    si.startea = cmd.ea;
    si.set_expr(switch_reg, dt_dword);
    si.defjump = defea;
    cmd = saved;
    setFlbits(cmd.ea, FF_JUMP);
    uFlag = getFlags(cmd.ea);
    set_switch_info_ex(cmd.ea, &si);
    create_switch_table(cmd.ea, &si);
    create_switch_xrefs(cmd.ea, &si);
    ok = true;
  }
  return ok;
}

//----------------------------------------------------------------------
// emulate operand
static void handle_operand(const op_t &op, bool loading)
{
  switch ( op.type )
  {
    // Address
    case o_near:
      // branch label - create code reference (call or jump
      // according to the instruction)
      {
        ea_t ea = toEA(cmd.cs, op.addr);
        cref_t ftype = fl_JN;
        if ( cmd.itype == m32r_bl && !handle_switch() )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        ua_add_cref(op.offb, ea, ftype);
      }
      break;

    // Immediate
    case o_imm:
      QASSERT(10135, loading);
      handle_imm();
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(uFlag, op.n) )
        ua_add_off_drefs2(op, dr_O, OOFW_IMM|OOF_SIGNED);

      // create a comment if this immediate is represented in the .cfg file
      {
        const ioport_t *port = find_sym(op.value);
        if ( port != NULL && !has_cmt(uFlag) )
            set_cmt(cmd.ea, port->cmt, false);
      }
      break;

    // Displ
    case o_displ:
      handle_imm();
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(uFlag, op.n) )
        ua_add_off_drefs2(op, loading ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR|OOFW_32);

      // create stack variables if required
      if ( may_create_stkvars() && !isDefArg(uFlag, op.n) )
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL && (op.reg == rFP || op.reg == rSP) && pfn->flags & FUNC_FRAME )
        {
          if ( ua_stkvar2(op, op.addr, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, op.n);
        }
      }
      break;

    case o_phrase:
      /* create stack variables if required */
      if ( op.specflag1 == fRI && may_create_stkvars() && !isDefArg(uFlag, op.n) )
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL
          && (op.reg == rFP || op.reg == rSP)
          && (pfn->flags & FUNC_FRAME) != 0 )
        {
          if ( ua_stkvar2(op, 0, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, op.n);
        }
      }
      break;

    // Phrase - register - void : do nothing
    case o_reg:
    case o_void:
        break;

    // Others types should never be called
    default:
      INTERR(10136);
  }
}

// emulate an instruction
int idaapi emu(void)
{
  uint32 feature = cmd.get_canon_feature();
  flow = ((feature & CF_STOP) == 0);

  if ( feature & CF_USE1)    handle_operand(cmd.Op1, 1 );
  if ( feature & CF_USE2)    handle_operand(cmd.Op2, 1 );
  if ( feature & CF_USE3)    handle_operand(cmd.Op3, 1 );

  if ( feature & CF_JUMP)    QueueSet(Q_jumps, cmd.ea );

  if ( feature & CF_CHG1)    handle_operand(cmd.Op1, 0 );
  if ( feature & CF_CHG2)    handle_operand(cmd.Op2, 0 );
  if ( feature & CF_CHG3)    handle_operand(cmd.Op3, 0 );

  if ( flow)    ua_add_cref(0, cmd.ea + cmd.size, fl_F );

  return 1;
}

bool idaapi create_func_frame(func_t *pfn) {
    if ( pfn == NULL )
        return 0;

    ea_t ea = pfn->startEA;
    insn_t insn[4];
    int i;

    for (i = 0; i < 4; i++) {
        decode_insn(ea);
        insn[i] = cmd;
        ea += cmd.size;
    }

    i = 0;
    ushort regsize = 0;            // number of saved registers

    // first insn is not either push fp OR st fp, @-sp
    if ( (insn[i].itype != m32r_push || insn[i].Op1.reg != rFP ) &&
        (insn[i].itype != m32r_st || insn[i].Op1.reg != rFP || insn[i].Op2.reg != rSP || insn[i].Op2.specflag1 != fRIAS))
    {
        return 0;
    }

    regsize += 4;
    i++;

    // next insn is push lr OR st lr, @-sp
    if ( (insn[i].itype == m32r_push && insn[i].Op1.reg == rLR ) ||
        (insn[i].itype == m32r_st && insn[i].Op1.reg == rFP && insn[i].Op2.reg == rLR && insn[i].Op2.specflag1 != fRIAS))
    {
        regsize += 4;
        i++;
    }

    // next insn is not addi sp, #imm
    if ( insn[i].itype != m32r_addi || insn[i].Op1.reg != rSP )
        return 0;

    sval_t offset = - (sval_t) insn[i].Op2.value;

    // toggle to the negative sign of the immediate operand of the addi insn
    if ( !is_invsign(insn[i].ea, get_flags_novalue(insn[i].ea), 2) )
      toggle_sign(insn[i].ea, 2);

    i++;

    // next insn is not mv fp, sp
    if ( insn[i].itype != m32r_mv || insn[i].Op1.reg != rFP || insn[i].Op2.reg != rSP )
        return 0;

#ifdef DEBUG
    msg("=> %d bytes\n", - (signed) insn[1].Op2.value);
#endif

    pfn->flags |= (FUNC_FRAME | FUNC_BOTTOMBP);
    return add_frame(pfn, offset, regsize, 0);
}

// should always returns 0
int idaapi m32r_get_frame_retsize(func_t *)
{
    return 0;
}

// check is the specified operand is relative to the SP register
int idaapi is_sp_based(const op_t &op)
{
  return OP_SP_ADD | (op.reg == rSP ? OP_SP_BASED : OP_FP_BASED);
}

bool idaapi can_have_type(op_t &x)
{
  switch ( x.type )
  {
    case o_imm:
    case o_displ:
      return 1;

    case o_phrase:
      if ( x.specflag1 == fRI )
        return 1;
      break;
  }
  return 0;
}
