// $Id: ana.cpp,v 1.13 2000/11/06 22:11:16 jeremy Exp $
//
// Copyright (c) 2000 Jeremy Cooper.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//    This product includes software developed by Jeremy Cooper.
// 4. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//
// TMS320C1X Processor module
//       Instruction decode.
//
#include "../idaidp.hpp"
#include "idp.hpp"
#include "tms320c1.hpp"
#include "ins.hpp"
#include "reg.hpp"

//
// After determining an instruction's opcode, ana() calls one of the
// functions below to decode its operands.
//
int ana_di       (u_int16_t); // direct/indirect instruction
int ana_di_shift (u_int16_t); // direct/indirect w/ shift instruction
int ana_di_port  (u_int16_t); // direct/indirect to/from I/O port
int ana_di_aux   (u_int16_t); // direct/indirect to AR register
int ana_imm_1    (u_int16_t); // immediate 1 bit
int ana_imm_8    (u_int16_t); // immediate 8 bits
int ana_imm_13   (u_int16_t); // immediate 13 bits
int ana_imm_8_aux(u_int16_t); // immediate 8 bits into AR register
int ana_flow     (void);      // flow control
int ana_empty    (void);      // no operands

//
// These functions in turn may call one of the functions below to help
// decode the individual operands within the instruction.
//
int ana_op_di    (op_t &, op_t &, u_int16_t); // direct/indirect operand
int ana_op_narp  (op_t &, u_int16_t);         // new ARP operand

//
// Due to limitations that IDA's some of IDA's helper functions have,
// they don't work well with processors whose byte size is greater
// than 8 bits.  (This processor has a 16-bit byte).  Therefore we
// have to make our own replacements for these functions.
//
ushort tms320c1x_ua_next_byte(void);


//lint -esym(714,ana)
int idaapi ana(void)
{
        u_int16_t opcode;

        //
        // Fetch the first 16 bits of the instruction.
        // (All instructions are at least 16 bits long).
        //
        opcode = tms320c1x_ua_next_byte();

        //
        // Decode the instruction in the opcode by sifting through the
        // various instruction bit masks.
        //

        //
        // 3-bit mask instructions:
        // MPYK
        //
        switch ( opcode & ISN_3_BIT_MASK ) {
        case ISN3_MPYK : cmd.itype = I_MPYK; return ana_imm_13(opcode);
        }

        //
        // 4-bit mask instructions:
        // ADD, LAC, SUB
        //
        switch ( opcode & ISN_4_BIT_MASK ) {
        case ISN4_ADD  : cmd.itype = I_ADD;  return ana_di_shift(opcode);
        case ISN4_LAC  : cmd.itype = I_LAC;  return ana_di_shift(opcode);
        case ISN4_SUB  : cmd.itype = I_SUB;  return ana_di_shift(opcode);
        }

        //
        // 5-bit mask instructions:
        // SACH, IN, OUT
        //
        switch ( opcode & ISN_5_BIT_MASK ) {
        case ISN5_SACH : cmd.itype = I_SACH; return ana_di(opcode);
        case ISN5_IN   : cmd.itype = I_IN;   return ana_di_port(opcode);
        case ISN5_OUT  : cmd.itype = I_OUT;  return ana_di_port(opcode);
        }

        //
        // 7-bit mask instructions:
        // LAR, LARK, SAR
        //
        switch ( opcode & ISN_7_BIT_MASK ) {
        case ISN7_LAR  : cmd.itype = I_LAR;  return ana_di_aux(opcode);
        case ISN7_LARK : cmd.itype = I_LARK; return ana_imm_8_aux(opcode);
        case ISN7_SAR  : cmd.itype = I_SAR;  return ana_di_aux(opcode);
        }

        //
        // 8-bit mask instructions:
        // ADDH, ADDS, AND, LACK, OR, SACL, SUBC, SUBH, XOR, ZALH, LDP, MAR,
        // LT, LTA, LTD, MPY, LST, SST, DMOV, TBLR, TBLW
        //
        switch ( opcode & ISN_8_BIT_MASK ) {
        case ISN8_ADDH : cmd.itype = I_ADDH; return ana_di(opcode);
        case ISN8_ADDS : cmd.itype = I_ADDS; return ana_di(opcode);
        case ISN8_AND  : cmd.itype = I_AND;  return ana_di(opcode);
        case ISN8_LACK : cmd.itype = I_LACK; return ana_imm_8(opcode);
        case ISN8_OR   : cmd.itype = I_OR;   return ana_di(opcode);
        case ISN8_SACL : cmd.itype = I_SACL; return ana_di(opcode);
        case ISN8_SUBC : cmd.itype = I_SUBC; return ana_di(opcode);
        case ISN8_SUBH : cmd.itype = I_SUBH; return ana_di(opcode);
        case ISN8_SUBS : cmd.itype = I_SUBS; return ana_di(opcode);
        case ISN8_XOR  : cmd.itype = I_XOR;  return ana_di(opcode);
        case ISN8_ZALH : cmd.itype = I_ZALH; return ana_di(opcode);
        case ISN8_ZALS : cmd.itype = I_ZALS; return ana_di(opcode);
        case ISN8_LDP  : cmd.itype = I_LDP;  return ana_di(opcode);
        case ISN8_MAR  : cmd.itype = I_MAR;  return ana_di(opcode);
        case ISN8_LT   : cmd.itype = I_LT;   return ana_di(opcode);
        case ISN8_LTA  : cmd.itype = I_LTA;  return ana_di(opcode);
        case ISN8_LTD  : cmd.itype = I_LTD;  return ana_di(opcode);
        case ISN8_MPY  : cmd.itype = I_MPY;  return ana_di(opcode);
        case ISN8_LST  : cmd.itype = I_LST;  return ana_di(opcode);
        case ISN8_SST  : cmd.itype = I_SST;  return ana_di(opcode);
        case ISN8_DMOV : cmd.itype = I_DMOV; return ana_di(opcode);
        case ISN8_TBLR : cmd.itype = I_TBLR; return ana_di(opcode);
        case ISN8_TBLW : cmd.itype = I_TBLW; return ana_di(opcode);
        }

        //
        // 15-bit mask instructions:
        // LARP, LDPK
        //
        switch ( opcode & ISN_15_BIT_MASK ) {
        // LARP is a synonym for a special case of MAR
        // case ISN15_LARP: cmd.itype = I_LARP; return ana_ar(opcode);
        case ISN15_LDPK: cmd.itype = I_LDPK; return ana_imm_1(opcode);
        }

        //
        // 16-bit mask instructions:
        // ABS, ZAC, APAC, PAC, SPAC, B, BANZ, BGEZ, BGZ, BIOZ, BLEZ, BLZ,
        // BNZ, BV, BZ, CALA, CALL, RET, DINT, EINT, NOP, POP, PUSH, ROVM,
        // SOVM
        //
        switch ( opcode & ISN_16_BIT_MASK ) {
        case ISN16_ABS : cmd.itype = I_ABS;  return ana_empty();
        case ISN16_ZAC : cmd.itype = I_ZAC;  return ana_empty();
        case ISN16_APAC: cmd.itype = I_APAC; return ana_empty();
        case ISN16_PAC : cmd.itype = I_PAC;  return ana_empty();
        case ISN16_SPAC: cmd.itype = I_SPAC; return ana_empty();
        case ISN16_B   : cmd.itype = I_B;    return ana_flow();
        case ISN16_BANZ: cmd.itype = I_BANZ; return ana_flow();
        case ISN16_BGEZ: cmd.itype = I_BGEZ; return ana_flow();
        case ISN16_BGZ : cmd.itype = I_BGZ;  return ana_flow();
        case ISN16_BIOZ: cmd.itype = I_BIOZ; return ana_flow();
        case ISN16_BLEZ: cmd.itype = I_BLEZ; return ana_flow();
        case ISN16_BLZ : cmd.itype = I_BLZ;  return ana_flow();
        case ISN16_BNZ : cmd.itype = I_BNZ;  return ana_flow();
        case ISN16_BV  : cmd.itype = I_BV;   return ana_flow();
        case ISN16_BZ  : cmd.itype = I_BZ;   return ana_flow();
        case ISN16_CALA: cmd.itype = I_CALA; return ana_empty();
        case ISN16_CALL: cmd.itype = I_CALL; return ana_flow();
        case ISN16_RET : cmd.itype = I_RET;  return ana_empty();
        case ISN16_DINT: cmd.itype = I_DINT; return ana_empty();
        case ISN16_EINT: cmd.itype = I_EINT; return ana_empty();
        case ISN16_NOP : cmd.itype = I_NOP;  return ana_empty();
        case ISN16_POP : cmd.itype = I_POP;  return ana_empty();
        case ISN16_PUSH: cmd.itype = I_PUSH; return ana_empty();
        case ISN16_ROVM: cmd.itype = I_ROVM; return ana_empty();
        case ISN16_SOVM: cmd.itype = I_SOVM; return ana_empty();
        }

        //
        // If control reaches this point, then the opcode does not represent
        // any known instruction.
        //
        return 0;
}

//
// ana_empty()
//
// Called to decode an 'empty' instruction's operands.
// (Very trivial, because an empty instruction has no operands).
//
int
ana_empty()
{
        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_flow()
//
// Called to decode a flow control instruction's operands.
// Decodes the branch address of the instruction.
//
// (Some flow control instructions have no arguments and are thus
// decoded by calling ana_empty()).
//
int
ana_flow()
{
        u_int16_t addr;

        //
        // Fetch the next 16 bits from the instruction; they
        // constitute the branch address.
        //
        addr = tms320c1x_ua_next_byte();

        //
        // Fill in the cmd structure to reflect the first (and only)
        // operand of this instruction as being a reference to the CODE segment.
        //
        cmd.Op1.type = o_near;
        cmd.Op1.addr = addr;

        //
        // Set the operand type to reflect the size of the address
        // in the instruction.  Technically this instructions address
        // value is one processor byte (16 bits), but when it comes to defining
        // operand value sizes, IDA thinks in terms of 8-bit bytes.
        // Therefore, we specify this value as a word.
        //
        cmd.Op1.dtyp = dt_word;

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_di(opcode)
//
// Called to decode a direct/indirect memory reference instruction's
// operands.
//
int
ana_di(u_int16_t opcode)
{
        //
        // Decode the direct or indirect memory reference made
        // by the instruction as its first operand and the new arp value
        // (if it exists) as its second operand.
        //
        if ( ana_op_di(cmd.Op1, cmd.Op2, opcode) == 0 ) {
                //
                // The operand was invalid.
                //
                return 0;
        }

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_di_shift(opcode)
//
// Called to decode a direct/indirect memory reference plus shift
// instruction's operands.
//
int
ana_di_shift(u_int16_t opcode)
{
        //
        // First, decode the direct or indirect memory reference made
        // by the instruction as its first operand, and the new arp
        // value (if it exists) as its third operand.
        //
        if ( ana_op_di(cmd.Op1, cmd.Op3, opcode) == 0 ) {
                //
                // The operand was invalid.
                //
                return 0;
        }

        //
        // Finally, decode the shift value as the instruction's second operand.
        //
        cmd.Op2.type  = o_imm;
        cmd.Op2.value = ISN_SHIFT(opcode);

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_di_port(opcode)
//
// Called to decode a direct/indirect memory reference to/from I/O port
// instruction's operands.
//
int
ana_di_port(u_int16_t opcode)
{
        //
        // First, decode the direct or indirect memory reference made
        // by the instruction as its first operand and the new arp value
        // (if it exists) as its third operand.
        //
        if ( ana_op_di(cmd.Op1, cmd.Op3, opcode) == 0 ) {
                //
                // The operand was invalid.
                //
                return 0;
        }

        //
        // Next, decode the port number as the instruction's second operand.
        //
        cmd.Op2.type  = o_imm;
        cmd.Op2.value = ISN_PORT(opcode);

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_di_aux(opcode)
//
// Called to decode a direct/indirect memory reference to/from auxiliary
// register instruction's operands.
//
int
ana_di_aux(u_int16_t opcode)
{
        //
        // First, decode the auxiliary register number as the instruction's
        // first operand.
        //
        cmd.Op1.type = o_reg;
        cmd.Op1.reg  = (ISN_AUX_AR(opcode) ? IREG_AR1 : IREG_AR0);

        //
        // Finally, decode the direct or indirect memory reference made
        // by the instruction as its second operand and the new arp
        // value (if it exists) as its third operand.
        //
        if ( ana_op_di(cmd.Op2, cmd.Op3, opcode) == 0 ) {
                //
                // The operand was invalid.
                //
                return 0;
        }

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_imm_1(opcode)
//
// Called to decode a 1 bit immediate value instruction's operands.
//
int
ana_imm_1(u_int16_t opcode)
{
        //
        // Decode the 1 bit immediate value in this instruction's opcode
        // and make an immediate value operand out of it.
        //
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = ISN_IMM1(opcode);
        cmd.Op1.dtyp  = dt_byte;  // This means an 8 bit value, rather than 16.

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_imm_8(opcode)
//
// Called to decode an 8 bit immediate value instruction's operands.
//
int
ana_imm_8(u_int16_t opcode)
{
        //
        // Decode the 8 bit immediate value in this instruction's opcode
        // and make an immediate value operand out of it.
        //
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = ISN_IMM8(opcode);
        cmd.Op1.dtyp  = dt_byte;  // This means an 8 bit value, rather than 16.

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_imm_13(opcode)
//
// Called to decode a 13 bit immediate value instruction's operands.
//
int
ana_imm_13(u_int16_t opcode)
{
        //
        // Decode the 13 bit immediate value in this instruction's opcode
        // and make an immediate value operand out of it.
        //
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = ISN_IMM13(opcode);
        cmd.Op1.dtyp  = dt_word;  // This means an 8 bit value, rather than 16.

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_imm_8_aux(opcode)
//
// Called upon to decode an immediate 8 bit to aux register instruction's
// operands.
//
int
ana_imm_8_aux(u_int16_t opcode)
{
        //
        // Decode the AR bit of the instruction to determine which auxiliary
        // register is being loaded.  Make this register the first operand.
        //
        cmd.Op1.type = o_reg;
        cmd.Op1.reg  = (ISN_AUX_AR(opcode) ? IREG_AR1 : IREG_AR0);

        //
        // Next, decode the 8 bit immediate value in the instruction and
        // make it the second operand.
        //
        cmd.Op2.type  = o_imm;
        cmd.Op2.value = ISN_IMM8(opcode);
        cmd.Op2.dtyp  = dt_word;  // This means an 8 bit value, rather than 16.

        //
        // Successful decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_op_di(addr_op, narp_op, opcode)
//
// Decodes the direct or indirect memory reference made in the instruction
// contained in 'opcode' and places the decoded information into the operand
// address operand 'operand' and the new ARP operand 'narp_op'.
//
// Returns instruction size on successful decode, 0 on illegal condition.
//
int
ana_op_di(op_t &addr_op, op_t &narp_op, u_int16_t opcode)
{
        //
        // Check the direct/indirect bit.  This determines whether the
        // opcode makes a direct memory reference via an immediate value,
        // or an indirect memory reference via the current auxiliary
        // register.
        //
        if ( ISN_DIRECT(opcode) ) {
                //
                // The direct bit is set.  This instruction makes a direct
                // memory reference to the memory location specified in its
                // immediate operand.
                //
                addr_op.type = o_mem;
                addr_op.dtyp = dt_byte; // This means an 8 bit value, rather than 16.
                addr_op.addr = ISN_DIR_ADDR(opcode);
        } else {
                //
                // The direct bit is reset.  This instruction makes an
                // indirect memory reference.
                //
                // Determine whether this is an AR post-increment,
                // post-decrement, or no change reference.
                //
                if ( ISN_INDIR_INCR(opcode) && ISN_INDIR_DECR(opcode) ) {
                        //
                        // Both the AR increment and AR decrement flags are
                        // set.  This is an illegal instruction.
                        //
                        return 0;
                } else if ( ISN_INDIR_INCR(opcode) ) {
                        //
                        // The AR increment flag is set.
                        // This is an AR increment reference.
                        //
                        addr_op.type   = o_phrase;
                        addr_op.phrase = IPH_AR_INCR;
                } else if ( ISN_INDIR_DECR(opcode) ) {
                        //
                        // The AR decrement flag is set.
                        // This is an AR decrement reference.
                        //
                        addr_op.type   = o_phrase;
                        addr_op.phrase = IPH_AR_DECR;
                } else {
                        //
                        // Neither the AR auto-increment or auto-decrement
                        // flags is set.  That makes this a regular AR
                        // indirect reference.
                        //
                        addr_op.type   = o_phrase;
                        addr_op.phrase = IPH_AR;
                }
                //
                // Next, decode the auxiliary register pointer change command,
                // if present, as the instruction's second operand.  If no
                // change is requested in this instruction, then the second operand
                // will not be filled in.
                //
                if ( ana_op_narp(narp_op, opcode) == 0 ) {
                        //
                        // The operand was invalid.
                        //
                        return 0;
                }
        }

        //
        // Successful operand decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// ana_op_narp(operand, opcode)
//
// Decodes the 'auxiliary-register-pointer-change' command that may
// be embededded in the opcode 'opcode' and places the information
// about the change in the operand 'operand'.  If the instruction does
// not have a pointer change request, then 'operand' is left alone.
//
// Returns instruction size on successful decode, 0 on illegal condition.
//
int
ana_op_narp(op_t &op, u_int16_t opcode)
{

        //
        // Determine if the instruction contains a request
        // to change the ARP register after execution.
        //
        if ( ISN_INDIR_NARP(opcode) ) {
                //
                // The instruction contains the request.
                // Reflect the request in the operand provided.
                //
                op.type   = o_reg;
                if ( ISN_INDIR_ARP(opcode) ) {
                        // Change to AR1
                        op.reg = IREG_AR1;
                } else {
                        // Change to AR0
                        op.reg = IREG_AR0;
                }
        }

        //
        // Successful operand decode.
        // Return the instruction size.
        //
        return cmd.size;
}

//
// tms320c1x_ua_next_byte()
//
// Simulates the effect of the IDA kernel helper function ua_next_byte(),
// but works with our 16-bit byte environment.
//
ushort
tms320c1x_ua_next_byte(void)
{
        ushort value;

        //
        // Fetch a 16 bit value from the (global) current instruction decode
        // pointer.
        //
        value = (ushort)get_full_byte(cmd.ea+cmd.size);

        //
        // Increment the size of the current instruction, to reflect the fact
        // that it contains the byte that we just read.
        //
        cmd.size++;

        return value;
}
