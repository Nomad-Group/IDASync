/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "7900.hpp"
#include <ints.hpp>


static bool flow;
//------------------------------------------------------------------------
// convert to data and add cross-ref
static void DataSet(op_t &x, ea_t EA, int isload)
{
  ua_dodata2(x.offb, EA, x.dtyp);
  ua_add_dref(x.offb, EA, isload ? dr_R : dr_W);
}

//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isAlt,int isload)
{
  switch ( x.type )
  {
    case o_phrase:
      //QueueSet(Q_jumps, cmd.ea);
    case o_void:
    case o_reg:
      break;

    case o_sr:
    case o_displ:
      doImmd(cmd.ea);
      if ( !isAlt )
      {
        uint32 offb;
        ushort addr = ushort(x.addr);
        if ( x.type == o_displ  )
        {
          addr += (ushort)cmd.ip;
          addr += cmd.size;
          offb = (uint32)toEA(codeSeg(addr,x.n), 0);
          DataSet(x, offb+addr, isload);
        }
        else if ( op_adds_xrefs(uFlag, x.n) )
        {
          reref:
            ea_t ea = ua_add_off_drefs2(x, dr_O, x.type == o_displ ? OOF_ADDR : 0);
          if ( x.type == o_displ )
            ua_dodata2(x.offb, ea, x.dtyp);
        }
        else if ( x.type == o_displ && !x.reg && !isDefArg(uFlag, x.n) )
        {
          if ( set_offset(cmd.ea, x.n, toEA(cmd.cs,0)) )
            goto reref;
        }
      }
      break;

    case o_stk:
    case o_imm:
      doImmd(cmd.ea);
      if ( op_adds_xrefs(get_flags_novalue(cmd.ea), x.n) )
        ua_add_off_drefs2(x, dr_O, 0);
      break;

    case o_ab:
      if ( x.TypeOper == TAB_INDIRECTED_ABS_X )
      {
        ea_t ea = toEA(cmd.cs, x.addr);
        ua_dodata2(x.offb, ea, dt_word);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);

        // get data
        uint32 Addr;
        Addr = get_word(ea);
        Addr = uint32( Addr | (getPG<<16));
        ua_add_cref(2, Addr, fl_JF);
      }
      else
      {
        DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
      }
      break;

    case o_mem:
      // convert to data, add cross ref
      switch ( x.TypeOper )
      {
        case TDIR_DIR_Y:
        case TDIR_DIR_X:
        case TDIR_DIR:
        case TDIR_INDIRECT_DIR:
        case TDIR_INDIRECT_DIR_X:
        case TDIR_INDIRECT_DIR_Y:
        case TDIR_L_INDIRECT_DIR:
        case TDIR_L_INDIRECT_DIR_Y:
          if ( getDPReg == 1 )
          {
            uint32 d = x.addr & 0xC;
            x.addr &= 0xFF3F;
            DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
            x.addr |=d;
          }
          else
          {
            DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
          }
          break;
        default:
          DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
          break;
      }
      break;

    case o_near:
      {
        ea_t ea = toEA(cmd.cs, x.addr);
        switch ( cmd.itype )
        {
          case m7900_jsr:
            ua_add_cref(x.offb, ea, fl_CN );
            if ( !func_does_return(ea) )
              flow = false;
            break;

          case m7900_jsrl:
            ua_add_cref(x.offb, ea, fl_CF);
            if ( !func_does_return(ea) )
              flow = false;
            break;

          case m7900_jmpl:
            ua_add_cref(x.offb, ea, fl_JF);
            break;

          default:
            ua_add_cref(x.offb, ea, fl_JN);
            break;
        }
      }
      break;

    default:
      //      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static void LDD(const insn_t &ins)
{
  static const int DPR[] = { rDPR0, rDPR1, rDPR2, rDPR3 };

  if ( ins.Op1.value==0x1 && ins.Op1.value==0x2 && ins.Op1.value==0x4 && ins.Op1.value==0x8 )
  {
    switch ( ins.Op1.value  )
    {
      case 0x1:
        split_srarea(ins.ea+ins.size, rDPR0, ins.Operands[1+0].value, SR_auto);
        break;

      case 0x2:
        split_srarea(ins.ea+ins.size, rDPR1, ins.Operands[1+1].value, SR_auto);
        break;

      case 0x4:
        split_srarea(ins.ea+ins.size, rDPR2, ins.Operands[1+2].value, SR_auto);
        break;

      case 0x8:
        split_srarea(ins.ea+ins.size, rDPR3, ins.Operands[1+3].value, SR_auto);
        break;
    }
  }
  else
  {
    for ( int i=0; i<4; i++ )
      if ( GETBIT(ins.Op1.value, i) == 1 )
        split_srarea(ins.ea+ins.size, DPR[i], ins.Operands[1+i].value, SR_auto);
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  //Set PG
  split_srarea(cmd.ea, rPG, ( cmd.ea & 0xFF0000 ) >> 16, SR_auto);

  uint32 Feature = cmd.get_canon_feature();
  flow = (Feature & CF_STOP) == 0;

  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);
  int flag4 = is_forced_operand(cmd.ea, 3);
  int flag5 = is_forced_operand(cmd.ea, 4);


  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) TouchArg(cmd.Op3, flag3, 1);
  if ( Feature & CF_USE4 ) TouchArg(cmd.Op4, flag4, 1);
  if ( Feature & CF_USE5 ) TouchArg(cmd.Op5, flag5, 1);

  if ( Feature & CF_JUMP ) QueueSet(Q_jumps, cmd.ea);

  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) TouchArg(cmd.Op3, flag3, 0);
  if ( Feature & CF_CHG4 ) TouchArg(cmd.Op4, flag4, 0);
  if ( Feature & CF_CHG5 ) TouchArg(cmd.Op5, flag5, 0);

  if ( flow )
    ua_add_cref(0, cmd.ea + cmd.size, fl_F);

  switch ( cmd.itype )
  {
    case m7900_lddn:
      //split_srarea(cmd.ea + cmd.size, GetDPR(), cmd.Op1.value, SR_auto);
      LDD(cmd);
      break;

    case m7900_ldt:
      split_srarea(cmd.ea + cmd.size, rDT, cmd.Op1.value, SR_auto);
      break;

    // clear m flag
    case m7900_clm:
      split_srarea(cmd.ea + cmd.size, rfM, 0, SR_auto);
      break;
    // set m flag
    case m7900_sem:
      split_srarea(cmd.ea + cmd.size, rfM, 1, SR_auto);
      break;

    // clear processor status
    case m7900_clp:
      // clear m flag
      if ( ((cmd.Op1.value & 0x20) >> 5) == 1 )
        split_srarea(cmd.ea + cmd.size, rfM, 0, SR_auto);
      // clear x flag
      if ( ((cmd.Op1.value & 0x10) >> 4) == 1 )
        split_srarea(cmd.ea + cmd.size, rfX, 0, SR_auto);
      break;

    // set processor status
    case m7900_sep:
      // set m flag
      if ( ((cmd.Op1.value & 0x20) >> 5) == 1 )
        split_srarea(cmd.ea + cmd.size, rfM, 1, SR_auto);
      // set x flag
      if ( ((cmd.Op1.value & 0x10) >> 4) == 1 )
        split_srarea(cmd.ea + cmd.size, rfX, 1, SR_auto);
      break;

    // pull processor status from stack
    case m7900_plp:
      split_srarea(cmd.ea + cmd.size, rfM, BADSEL, SR_auto);
      split_srarea(cmd.ea + cmd.size, rfX, BADSEL, SR_auto);
      break;

  }
  return 1;
}
