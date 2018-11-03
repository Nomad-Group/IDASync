
#ifndef __M7700_HPP
#define __M7700_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <segregs.hpp> // for get_sreg()

// flags for insn.op[n].specflag1
#define OP_IMM_WITHOUT_SHARP    0x0001  // don't display the # for this immediate
#define OP_ADDR_IND             0x0002  // this address should be printed between '(' ')'
#define OP_DISPL_IND            0x0004  // this displacement should be printed between '(' ')'
#define OP_DISPL_IND_P1         0x0008  // only the first parameter of the displacement
                                        // should be printed between '(' ')'
#define OP_ADDR_R               0x0010  // addr operand used in 'read' context
#define OP_ADDR_W               0x0020  // addr operand used in 'write' context
#define OP_ADDR_DR_REL          0x0040  // addr operand is relative to DR (direct page register)

// specflag1 helpers
inline bool is_imm_without_sharp(const op_t &op) { return (op.specflag1 & OP_IMM_WITHOUT_SHARP) != 0; }
inline bool is_addr_ind(const op_t &op)          { return (op.specflag1 & OP_ADDR_IND) != 0; }
inline bool is_addr_read(const op_t &op)         { return (op.specflag1 & OP_ADDR_R) != 0; }
inline bool is_addr_write(const op_t &op)        { return (op.specflag1 & OP_ADDR_W) != 0; }
inline bool is_displ_ind(const op_t &op)         { return (op.specflag1 & OP_DISPL_IND) != 0; }
inline bool is_displ_ind_p1(const op_t &op)      { return (op.specflag1 & OP_DISPL_IND_P1) != 0; }
inline bool is_addr_dr_rel(const op_t &op)       { return (op.specflag1 & OP_ADDR_DR_REL) != 0; }

// flags for insn.auxpref
#define INSN_LONG_FORMAT        0x0001  // we need to write an additionnal 'l'
                                        // after the insn mnemonic.
// auxpref helpers
inline bool is_insn_long_format(const insn_t &insn) { return (insn.auxpref & INSN_LONG_FORMAT) != 0; }

// flags for ash.uflag
#define UAS_SEGM                0x0001  // segments are named "segment XXX"
#define UAS_INDX_NOSPACE        0x0002  // no spaces between operands in indirect X addressing mode
#define UAS_END_WITHOUT_LABEL   0x0004  // do not print the entry point label after end directive
#define UAS_DEVICE_DIR          0x0008  // supports device declaration directives
#define UAS_BITMASK_LIST        0x0010  // supports list instead of bitmask for some special insn
                                        // like clp, psh...

// 7700 registers
enum m7700_registers
{
  rA,     // accumulator A
  rB,     // accumulator B
  rX,     // index X
  rY,     // index Y
  rS,     // stack pointer
  rPC,    // program counter
  rPG,    // program bank register
  rDT,    // data bank register
  rPS,    // processor status register
  rDR,    // direct page register
  rfM,    // data length flag
  rfX,    // index register length flag
  rVcs, rVds     // these 2 registers are required by the IDA kernel
};

// this module supports 2 processors: m7700, m7750
enum processor_subtype_t
{
  prc_m7700 = 0,
  prc_m7750 = 1
};

extern processor_subtype_t ptype;

extern qstring device;

// shortcut for a new operand type
#define o_bit              o_idpspec0

// exporting our routines
void idaapi m7700_header(outctx_t &ctx);
void idaapi m7700_footer(outctx_t &ctx);
void idaapi m7700_segstart(outctx_t &ctx, segment_t *seg);
void idaapi m7700_assumes(outctx_t &ctx);
int idaapi ana(insn_t *_insn);
int idaapi emu(const insn_t &insn);
const ioport_bit_t *find_bit(ea_t address, size_t bit);
bool idaapi create_func_frame(func_t *pfn);
int idaapi idp_get_frame_retsize(const func_t *pfn);

#endif // __M7700_HPP
