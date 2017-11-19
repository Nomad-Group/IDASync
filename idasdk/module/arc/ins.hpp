
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INS_HPP
#define __INS_HPP

extern instruc_t Instructions[];

enum nameNum
{

  ARC_null = 0,                 // Unknown Operation

  ARC_ld,                       // Load
  ARC_lr,                       // Load from auxiliary register
  ARC_st,                       // Store
  ARC_sr,                       // Store to auxiliary register
  ARC_store_instructions = ARC_sr,
  ARC_flag,                     // Set flags
  ARC_asr,                      // Arithmetic shift right
  ARC_lsr,                      // Logical shift right
  ARC_sexb,                     // Sign extend byte
  ARC_sexw,                     // Sign extend word
  ARC_extb,                     // Zero extend byte
  ARC_extw,                     // Zero extend word
  ARC_ror,                      // Rotate right
  ARC_rrc,                      // Rotate right through carry
  ARC_b,                        // Branch
  ARC_bl,                       // Branch and link
  ARC_lp,                       // Zero-overhead loop setup
  ARC_j,                        // Jump
  ARC_jl,                       // Jump and link
  ARC_add,                      // Add
  ARC_adc,                      // Add with carry
  ARC_sub,                      // Subtract
  ARC_sbc,                      // Subtract with carry
  ARC_and,                      // Logical bitwise AND
  ARC_or,                       // Logical bitwise OR
  ARC_bic,                      // Logical bitwise AND with invert
  ARC_xor,                      // Logical bitwise exclusive-OR

  // pseudo instructions
  ARC_mov,                      // Move
  ARC_nop,                      // No operation
  ARC_lsl,                      // Logical shift left
  ARC_rlc,                      // Rotate left through carry

  // arc7
  ARC_brk,                      // Breakpoint
  ARC_sleep,                    // Sleep until interrupt or restart

  // arc8
  ARC_swi,                      // Software interrupt

  // extra optional instrutions
  ARC_asl,                      // Arithmetic shift left
  ARC_mul64,                    // Signed 32x32 multiply
  ARC_mulu64,                   // Unsigned 32x32 multiply
  ARC_max,                      // Maximum of two signed integers
  ARC_min,                      // Minimum of two signed integers
  ARC_swap,                     // Exchange upper and lower 16 bits
  ARC_norm,                     // Normalize (find-first-bit)

  // ARCompact instructions
  ARC_bbit0,                    // Branch if bit cleared to 0
  ARC_bbit1,                    // Branch if bit set to 1
  ARC_br,                       // Branch on compare
  ARC_pop,                      // Restore register value from stack
  ARC_push,                     // Store register value on stack

  ARC_abs,                      // Absolute value
  ARC_add1,                     // Add with left shift by 1 bit
  ARC_add2,                     // Add with left shift by 2 bits
  ARC_add3,                     // Add with left shift by 3 bits
  ARC_bclr,                     // Clear specified bit (to 0)
  ARC_bmsk,                     // Bit Mask
  ARC_bset,                     // Set specified bit (to 1)
  ARC_btst,                     // Test value of specified bit
  ARC_bxor,                     // Bit XOR
  ARC_cmp,                      // Compare
  ARC_ex,                       // Atomic Exchange
  ARC_mpy,                      // Signed 32x32 multiply (low)
  ARC_mpyh,                     // Signed 32x32 multiply (high)
  ARC_mpyhu,                    // Unsigned 32x32 multiply (high)
  ARC_mpyu,                     // Unsigned 32x32 multiply (low)
  ARC_neg,                      // Negate
  ARC_not,                      // Logical bit inversion
  ARC_rcmp,                     // Reverse Compare
  ARC_rsub,                     // Reverse Subtraction
  ARC_rtie,                     // Return from Interrupt/Exception
  ARC_sub1,                     // Subtract with left shift by 1 bit
  ARC_sub2,                     // Subtract with left shift by 2 bits
  ARC_sub3,                     // Subtract with left shift by 3 bits
  ARC_sync,                     // Synchronize
  ARC_trap,                     // Raise an exception
  ARC_tst,                      // Test
  ARC_unimp,                    // Unimplemented instruction

  ARC_abss,                     // Absolute and saturate
  ARC_abssw,                    // Absolute and saturate of word
  ARC_adds,                     // Add and saturate
  ARC_addsdw,                   // Add and saturate dual word
  ARC_asls,                     // Arithmetic shift left and saturate
  ARC_asrs,                     // Arithmetic shift right and saturate
  ARC_divaw,                    // Division assist
  ARC_negs,                     // Negate and saturate
  ARC_negsw,                    // Negate and saturate of word
  ARC_normw,                    // Normalize to 16 bits
  ARC_rnd16,                    // Round to word
  ARC_sat16,                    // Saturate to word
  ARC_subs,                     // Subtract and saturate
  ARC_subsdw,                   // Subtract and saturate dual word

  // mac d16
  ARC_muldw, 
  ARC_muludw,
  ARC_mulrdw,
  ARC_macdw, 
  ARC_macudw,
  ARC_macrdw,
  ARC_msubdw,

  // 32x16 MUL/MAC
  ARC_mululw,
  ARC_mullw,
  ARC_mulflw,
  ARC_maclw,
  ARC_macflw,
  ARC_machulw,
  ARC_machlw,
  ARC_machflw,
  ARC_mulhlw,
  ARC_mulhflw,

  ARC_last,

};

#endif
