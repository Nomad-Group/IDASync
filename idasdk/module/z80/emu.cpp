/*
 *      Interactive disassembler (IDA).
 *      Version 3.06
 *      Copyright (c) 1990-96 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i5.hpp"

static bool flow;

//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( !is_defarg(get_flags(insn.ea), n) )
  {
    switch ( insn.itype )
    {
      case I5_ani:
      case I5_xri:
      case I5_ori:
      case I5_in:
      case I5_out:
      case I5_rst:

      case HD_in0:
      case HD_out0:
      case HD_tstio:
        op_num(insn.ea,-1);
        break;
    }
  }
}

//----------------------------------------------------------------------
static void load_operand(const insn_t &insn, const op_t &x)
{
  dref_t xreftype;
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
    default:
      break;

    case o_imm:
      xreftype = dr_O;
MakeImm:
      set_immd_bit(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, xreftype, 0);
      break;
    case o_displ:
      xreftype = dr_R;
      goto MakeImm;

    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        insn.add_dref(ea, x.offb, dr_R);
        insn.create_op_data(ea, x);
      }
      break;

    case o_near:
      {
        ea_t ea = map_code_ea(insn, x);
        ea_t segbase = (ea - x.addr) >> 4;
        ea_t thisseg = insn.cs;
        int iscall = has_insn_feature(insn.itype,CF_CALL);
        insn.add_cref(
                ea,
                x.offb,
                iscall ? (segbase == thisseg ? fl_CN : fl_CF)
                       : (segbase == thisseg ? fl_JN : fl_JF));
        if ( iscall && !func_does_return(ea) )
          flow = false;
      }
      break;
  }
}

//----------------------------------------------------------------------
static void save_operand(const insn_t &insn, const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        insn.create_op_data(ea, x);
        insn.add_dref(ea, x.offb, dr_W);
      }
      break;
    case o_displ:
      set_immd_bit(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_W, OOF_ADDR);
    case o_phrase:
      break;
    default:
      switch ( insn.itype )
      {
        case Z80_in0:
        case Z80_outaw:
          break;
        default:
          break;
      }
      break;
  }
}

//----------------------------------------------------------------------
int idaapi i5_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  if ( (Feature & CF_USE1) )
    load_operand(insn, insn.Op1);
  if ( (Feature & CF_USE2) )
    load_operand(insn, insn.Op2);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  switch ( insn.itype )
  {
    case I5_mov:
    case I5_mvi:
    case Z80_ld:
        break;
    case Z80_jp:
    case Z80_jr:                // Z80
    case Z80_ret:               // Z80
        if ( insn.Op1.Cond != oc_not )
          break;
        // no break
    case I5_jmp:
        if ( insn.Op2.type == o_phrase )
          remember_problem(PR_JUMP, insn.ea);
        // fallthrough
    case I5_ret:
        flow = false;
        break;
    case I5_rstv:
        add_cref(insn.ea, map_code_ea(insn, 0x40, 0), fl_CN);
        break;
    case I5_rst:
        {
          int mul = (isZ80() ? 1 : 8);
          ushort offset = ushort(insn.Op1.value * mul);
          add_cref(insn.ea, map_code_ea(insn, offset, 0), fl_CN);
        }
    case I5_call:
    case I5_cc:
    case I5_cnc:
    case I5_cz:
    case I5_cnz:
    case I5_cpe:
    case I5_cpo:
    case I5_cp:
    case I5_cm:
    case Z80_exx:               // Z80
//        i5_CPUregs.bc.undef();
//        i5_CPUregs.de.undef();
//        i5_CPUregs.hl.undef();
//        i5_CPUregs.af.undef();
//        i5_CPUregs.ix.undef();
//        i5_CPUregs.iy.undef();
        break;
    default:
//        R1.undef();
//        R2.undef();
        break;
  }

  if ( Feature & CF_CHG1 )
    save_operand(insn, insn.Op1);
  if ( Feature & CF_CHG2 )
    save_operand(insn, insn.Op2);

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
