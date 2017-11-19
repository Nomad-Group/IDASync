/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"

static bool flow;

//----------------------------------------------------------------------
// Calculate the target data address
ea_t map_addr(asize_t off, int opnum, bool isdata)
{
  if ( isdata )
  {
    if ( isOff(uFlag, opnum) )
      return get_offbase(cmd.ea, opnum) >> 4;
    return intmem + off;
  }
  return toEA(codeSeg(off, opnum), off);
}

//----------------------------------------------------------------------
static void TouchArg(op_t &x, int isload)
{
  switch ( x.type )
  {
    case o_displ:
    case o_imm:
      if ( op_adds_xrefs(uFlag, x.n) )
      {
        int outf = x.type != o_imm ? OOF_ADDR : 0;
        ua_add_off_drefs2(x, dr_O, outf|OOF_SIGNED);
      }
      break;

    case o_mem:
    case o_ind_mem:
    case o_reg:
    case o_ind_reg:
      {
        ea_t dea;
        if ( x.type == o_mem || x.type == o_ind_mem )
        {
          dea = map_addr(x.addr, x.n, true);
        }
        else
        {
          if ( x.reg >= rRR0 )
            dea = map_addr(x.reg - rRR0, x.n, true);
          else
            dea = map_addr(x.reg - rR0, x.n, true);
        }
        ua_dodata2(x.offb, dea, x.dtyp);
        if ( !isload )
          doVar(dea);
        ua_add_dref(x.offb, dea, isload ? dr_R : dr_W);
        if ( !has_user_name(get_flags_novalue(dea)) && dea > intmem)
        {
          char buf[10];
          int num = dea - intmem;
          if ( num < 0x100 )
          {
            qsnprintf(buf, sizeof(buf), "R%d", num);
          }
          else if ( num < 0x1000 )
          {
            qsnprintf(buf, sizeof(buf), "ERF_%X_%d", num >> 8, num & 0xFF);
          }
          else
          {
            int reg_no     = ((num >> 4) & 0xF0) + (num & 0xF);
            int subbank_no = ((num >> 4) & 0xF) + 1;
            qsnprintf(buf, sizeof(buf), "R%d_%X", reg_no, subbank_no);
          }
          set_name(dea, buf, SN_NOWARN);
        }
      }
      break;

    case o_near:
      {
        ea_t ea = map_addr(x.addr, x.n, false);
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
          flow = func_does_return(ea);
      }
      break;

  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();

  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, 1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, 1);
  if ( Feature & CF_JUMP ) QueueSet(Q_jumps, cmd.ea);

  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, 0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, 0);

  if ( flow )
    ua_add_cref(0, cmd.ea+cmd.size, fl_F);

  if ( cmd.itype == Z8_srp // Set register pointer
    || (cmd.itype == Z8_pop && cmd.Op1.type == o_mem && cmd.Op1.addr == 0xFD) ) // popping RP
  {
    // set the RP value
    sel_t val = cmd.itype == Z8_srp ? (cmd.Op1.value & 0xFF) : BADSEL;
    split_srarea(cmd.ea + cmd.size, rRp, val, SR_auto, true);
  }
  return 1;
}
