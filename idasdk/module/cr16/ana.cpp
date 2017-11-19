
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

static uchar near Rproc(uchar code)
{
  switch (code)
  {
    case 0x1:
      return (rPSR);
    case 0x3:
      return (rINTBASE);
    case 0x4:
      return (rINTBASEH);
    case 0x5:
      return (rCFG);
    case 0x7:
      return (rDSR);
    case 0x9:
      return (rDCR);
    case 0xB:
      return (rISP);
    case 0xD:
      return (rCARL);
    case 0xE:
      return (rCARH);
  }
  return (0);
}

// immediate operands
static void near SetImmData(op_t & op, int32 code, int bits)
{
  // extend sign
  if (code & (1 << bits))
    code -= 1L << (bits + 1);
  op.type = o_imm;
  // always in the second byte
  op.offb = 1;
  // data size
  op.dtyp = bits > 8 ? (bits > 16 ? dt_dword : dt_word) : dt_byte;
  // value
  op.addr = op.value = code;
}

// register operand
static void near SetReg(op_t & op, uchar reg_n)
{
  op.type = o_reg;
  op.reg  = reg_n;
  op.dtyp = dt_word;
}


/*
// memory address
static void near SetMemVar(op_t &op, ea_t addr)
{
  op.type = o_mem;
  op.addr = addr;
  op.dtyp = dt_word;
}
*/

// relative jump
static void near SetRelative(op_t & op, int32 disp, int bits)
{
  op.type = o_near;
  op.dtyp = dt_word;
  op.offb = 0;
  // sign extend
  if (disp & (1 << bits))
    disp -= 1L << (bits + 1);
  op.addr = cmd.ip + disp;
}

unsigned short GetWord(void)
{
  unsigned short wrd;
  wrd = ua_next_byte();
  wrd |= ((unsigned short) ua_next_byte()) << 8;
  return (wrd);
}

// store/load operands
static void near SetSL(op_t & op, unsigned short code)
{
  op.reg = rR0 + ((code >> 1) & 0x0F);
  op.dtyp = (code & 0x2000) ? dt_word : dt_byte;
  if (code & 1)
  {
    if (code & 0x1000)
    {
      if (code & 0x800)
      {
        if ((code & 0x1F) == 0x1F)
        {
          // absolute addr
          op.type = o_mem;
          op.addr = op.value = GetWord() | (((uint32) code & 0x600) << 11);
        }
        else
        {                       // reg pair
          op.type = o_displ;
          op.addr = op.value = GetWord() | (((uint32) code & 0x600) << 11);
          op.specflag1 |= URR_PAIR;
        }
      }
      else
      {                         // reg base
        op.type = o_displ;
        op.addr = op.value = GetWord() | (((uint32) code & 0x600) << 11);
      }
    }
    else
    {                           // Offset
      op.type = o_displ;
      op.addr = op.value = ((code >> 8) & 0x1E) | 1;
    }
  }
  else
  {
    op.type = o_displ;
    op.addr = op.value = (code >> 8) & 0x1E;
  }
}

static void near ClearOperand(op_t & op)
{
  op.dtyp = dt_byte;
  op.type = o_void;
  op.specflag1 = 0;
  op.specflag2 = 0;
  op.offb = 0;
  op.offo = 0;
//op.flags=0;
  op.reg = 0;
  op.value = 0;
  op.addr = 0;
  op.specval = 0;
}

#define EXTOPS uint16(-2)
static const uint16 Ops[16] = 
{
  CR16_addb,  CR16_addub, EXTOPS,    CR16_mulb,
  CR16_ashub, CR16_lshb,  CR16_xorb, CR16_cmpb,
  CR16_andb,  CR16_addcb, CR16_br,   CR16_tbit,
  CR16_movb,  CR16_subcb, CR16_orb,  CR16_subb,
};

static const uint16 ExtOps[16] = 
{
  CR16_cbitb, CR16_sbitb, CR16_tbitb, CR16_storb,
};

// extended instructions
// register-relative with no displacement:
// 54 3 2109 8   76     5  4321        d
// 01 i 0010 bs1 ex-op bs0 bit-num/Imm 1
// register-relative with 16-bit displacement:
// 54 3 2109 8   76     5  4321        d
// 00 i 0010 bs1 ex-op bs0 bit-num/Imm 1
// 18-bit absolute memory:
// 54 3 2109 8   76     5  4321        d
// 00 i 0010 bs1 ex-op bs0 bit-num/Imm 0
static void near SetExtOp(unsigned short code)
{
  if ( code & 1 )
  {
    // Register-relative
    cmd.Op2.reg = rR0 + ((code >> 5) & 9);
    cmd.Op2.type = o_displ;
    cmd.Op2.dtyp = (code & 0x2000) ? dt_word : dt_byte;
    if ( (code >> 14) & 1 )
    {
      // no displacement
      cmd.Op2.addr = 0;
    }
    else
    {
      cmd.Op2.addr = GetWord();
    }
  }
  else
  {
    // 18-bit absolute memory
    cmd.Op2.type = o_mem;
    cmd.Op2.dtyp = (code & 0x2000) ? dt_word : dt_byte;
    int adext = ((code >> 7) & 2) | ((code >> 5) & 1);
    cmd.Op2.addr = GetWord() | (adext<<16);
  }
  cmd.Op1.type = o_imm;
  cmd.Op1.value = (code >> 1) & 0xF;
}

//----------------------------------------------------------------------
// analyzer
int idaapi CR16_ana(void)
{
  ushort code;
  uchar WordFlg;
  uchar OpCode;
  uchar Oper1;
  uchar Oper2;

  ClearOperand(cmd.Op1);
  ClearOperand(cmd.Op2);
  if (cmd.ip & 1)
    return (0);
  
  // get instruction word
  code = GetWord();

  WordFlg = (code >> 13) & 1;
  OpCode = (code >> 9) & 0x0F;
  Oper1 = (code >> 5) & 0x0F;
  Oper2 = (code >> 1) & 0x0F;


  switch ((code >> 14) & 3)
  {
    // register-register op and special OP
    case 0x01:
      if (code & 1)
      {
        // 01xxxxxxxxxxxxx1
        switch ((cmd.itype = Ops[OpCode]))
        {
          case 0:
            return (0);
          case EXTOPS:
            {
              int exop = (Oper1 >> 1) & 3;
              cmd.itype = ExtOps[exop] + WordFlg;
              SetExtOp(code);
            }
            break;
            // branch's
          case CR16_br:
            if (WordFlg)
            {
              cmd.itype = CR16_jal;
              SetReg(cmd.Op1, rR0 + Oper1);
              SetReg(cmd.Op2, rR0 + Oper2);
            }
            else
            {
              cmd.itype = CR16_jeq + Oper1;
              SetReg(cmd.Op1, rR0 + Oper2);
            }
            break;
            // Special tbit
          case CR16_tbit:
            if (WordFlg == 0)
              return (0);
            cmd.itype--;
            // all other cmds
          default:             // fix word operations
            if (WordFlg)
              cmd.itype++;
            // Setup register OP
            SetReg(cmd.Op2, rR0 + Oper1);
            // Setup register OP
            SetReg(cmd.Op1, rR0 + Oper2);
            break;
        }
      }
      else
      {                         // 01xxxxxxxxxxxxx0
        if (WordFlg)
        {
          // 011xxxxxxxxxxxx0
          static const unsigned char SCmd[16] = {
            CR16_mulsb, CR16_mulsw, CR16_movd, CR16_movd,
            CR16_movxb, CR16_movzb, CR16_push, CR16_seq,
            CR16_lpr,   CR16_spr,   CR16_beq,  CR16_bal,
            CR16_retx,  CR16_excp,  CR16_di,   CR16_wait
          };
          switch ((cmd.itype = SCmd[OpCode]))
          {
            case 0:
              return (0);

            case CR16_beq:
            {
              // 01 1 1010    cond   d16,d19-d17 0
              cmd.itype = CR16_beq + Oper1;
              int disp = GetWord();
              disp |= (Oper2 & 8) << (16-3);
              disp |= (Oper2 & 7) << 17;
              SetRelative(cmd.Op1, disp, 20);
            }
            break;

            case CR16_push:
            {
              static const unsigned char PQ[4] = {
                CR16_push,   CR16_pop,
                CR16_popret, CR16_popret
              };
              if ( Oper1 > 15 )
                return 0;
              cmd.itype = PQ[Oper1 >> 2];
              SetReg(cmd.Op2, rR0 + Oper2);
              SetImmData(cmd.Op1, (Oper1 & 3) + 1, 4);
              break;
            }

            case CR16_mulsw:
              SetReg(cmd.Op2, rR0 + Oper1);
              SetReg(cmd.Op1, rR0 + Oper2);
              cmd.Op2.specflag1 |= URR_PAIR;
              break;

            case CR16_movd:
              SetReg(cmd.Op2, rR0 + Oper2);
              cmd.Op2.specflag1 |= URR_PAIR;
              // !!!! ADD HIIIII ?!?!?!?
              SetImmData(cmd.Op1, GetWord(), 20);
              break;
            case CR16_excp:
              if (Oper1 != 0x0F)
                return (0);
              SetImmData(cmd.Op1, Oper2, 4);
              break;

            case CR16_retx:
              if (Oper1 != 0x0F)
                return (0);
              if (Oper2 != 0x0F)
                return (0);
              break;

            case CR16_wait:
              if (Oper1 == 0x0F)
              {
                if (Oper2 == 0x0F)
                  break;
                if (Oper2 == 0x03)
                {
                  cmd.itype = CR16_eiwait;
                  break;
                }
              }
              if ((code & 0x19E) == 0x84)
              {
                cmd.itype = CR16_storm;
                SetImmData(cmd.Op1, (Oper2 & 3) + 1, 8);
                break;
              }
              if ((code & 0x19E) == 0x04)
              {
                cmd.itype = CR16_loadm;
                SetImmData(cmd.Op1, (Oper2 & 3) + 1, 8);
                break;
              }
              if ((Oper2 & 0x6) == 0)
              {
                cmd.itype = CR16_muluw;
                SetReg(cmd.Op2, rR0 + Oper1);
                SetReg(cmd.Op1, rR0 + Oper2);
                cmd.Op2.specflag1 |= URR_PAIR;
                break;
              }

              return (0);

            case CR16_di:
              if (Oper2 != 0x0F)
                return (0);
              switch (Oper1)
              {
                case 0x0F:
                  cmd.itype = CR16_ei;
                case 0x0E:
                  break;
                default:
                  return (0);
              }
              break;

            case CR16_seq:
              SetReg(cmd.Op1, rR0 + Oper2);
              if (Oper1 > 0x0D)
                return (0);
              cmd.itype = CR16_seq + Oper1;
              break;

            case CR16_lpr:
              SetReg(cmd.Op1, rR0 + Oper2);
              Oper1 = Rproc(Oper1);
              if (Oper1 == 0)
                return (0);
              SetReg(cmd.Op2, Oper1);
              break;

            case CR16_spr:
              SetReg(cmd.Op2, rR0 + Oper2);
              Oper1 = Rproc(Oper1);
              if (Oper1 == 0)
                return (0);
              SetReg(cmd.Op1, Oper1);
              break;

            case CR16_bal:
              {
                // 01 1 1011 lnk-pair  d16,d19-d17 0
                SetReg(cmd.Op1, rR0 + Oper1);
                cmd.Op1.specflag1 |= URR_PAIR;
                int disp = GetWord();
                disp |= (Oper2 & 8) << (16-3);
                disp |= (Oper2 & 7) << 17;
                SetRelative(cmd.Op2, disp, 20);
              }
              break;

            default:
              SetReg(cmd.Op2, rR0 + Oper1);
              SetReg(cmd.Op1, rR0 + Oper2);
              break;
          }
        }
        else
        {                       // jump's
          // 010xxxxxxxxxxxx0
          cmd.itype = CR16_beq + Oper1;
          SetRelative(cmd.Op1, (code & 0x1E) | (OpCode << 5), 8);
        }
      }
      break;

      // short immediate-register (two word)
    case 0x00:
      switch ((cmd.itype = Ops[OpCode]))
      {
        case 0:
          return (0);
          // branch's
        case CR16_br:
          if (code & 1)
          {
            static const unsigned char BQ[4] = {
              CR16_beq0b, CR16_beq1b,
              CR16_bne0b, CR16_bne1b
            };
            cmd.itype = BQ[(Oper1 >> 1) & 3];
            if (WordFlg)
              cmd.itype++;
            SetReg(cmd.Op1, rR0 + (Oper1 & 0x9));
            SetRelative(cmd.Op1, code & 0x1E, 5);
          }
          else if (WordFlg)
          {
            cmd.itype = CR16_bal;
            SetReg(cmd.Op1, rR0 + Oper1);
            if ((code & 0x0F) == 0x0E)
            {
              SetRelative(cmd.Op2,
                          GetWord() | (((uint32) code & 0x10) << 12), 16);
              cmd.Op2.addr = cmd.Op2.value = cmd.Op2.addr & 0x1FFFF;
            }
            else
              SetRelative(cmd.Op2, code & 0x1F, 4);
          }
          else
          {
            cmd.itype = CR16_beq + Oper1;
            if ((code & 0x0F) == 0x0E)
            {
              SetRelative(cmd.Op1,
                          GetWord() | (((uint32) code & 0x10) << 12), 16);
              cmd.Op1.addr = cmd.Op1.value = cmd.Op2.addr & 0x1FFFF;
            }
            else
            {
              SetRelative(cmd.Op1, code & 0x1F, 4);
            }
          }
          break;

        case EXTOPS:
          {
            // 54 3 2109 8   76     5  4321        d
            // 00 i 0010 bs1 ex-op bs0 bit-num/Imm d
            int exop = (Oper1 >> 1) & 3;
            cmd.itype = ExtOps[exop] + WordFlg;
            SetExtOp(code);
          }
          break;

          // Special tbit
        case CR16_tbit:
          if (WordFlg == 0)
          {
            // jcond large format
            // 00 0 1011 cond target-pair 1
            // jal large format
            // 00 0 1011 link-pair target-pair 0
            if ( code & 1 )
            {
              cmd.itype = CR16_jeq + Oper1;
              SetReg(cmd.Op1, rR0 + Oper2);
              cmd.Op1.specflag1 |= URR_PAIR;
            }
            else
            {
              cmd.itype = CR16_jal;
              SetReg(cmd.Op1, rR0 + Oper1);
              cmd.Op1.specflag1 |= URR_PAIR;
              SetReg(cmd.Op2, rR0 + Oper2);
              cmd.Op2.specflag1 |= URR_PAIR;
            }
            break;
          }
          cmd.itype--;

          // all other cmds
        default:
          if ( code == 0x200 )
          {
            cmd.itype = CR16_nop;
            break;
          }
          if (WordFlg) // fix word operations
            cmd.itype++;
          // Setup register OP
          SetReg(cmd.Op2, rR0 + Oper1);
          // Setup immediate
          if ((code & 0x1F) == 0x11)
            SetImmData(cmd.Op1, GetWord(), 15);
          else
            SetImmData(cmd.Op1, code & 0x1F, 4);
          break;
      }
      break;

      // LOADi
    case 0x02:
      cmd.itype = WordFlg ? CR16_loadw : CR16_loadb;
      SetReg(cmd.Op2, rR0 + Oper1);
      SetSL(cmd.Op1, code);
      break;
      // STORi
    case 0x3:
      cmd.itype = WordFlg ? CR16_storw : CR16_storb;
      SetReg(cmd.Op1, rR0 + Oper1);
      SetSL(cmd.Op2, code);
      break;
  }
  return cmd.size;
}
