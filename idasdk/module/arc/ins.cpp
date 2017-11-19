/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "arc.hpp"

instruc_t Instructions[] = {

{ "",           0                               },      // Unknown Operation
{ "ld",         CF_CHG1|CF_USE2                 },      // Load
{ "lr",         CF_CHG1|CF_USE2                 },      // Load from auxiliary register
{ "st",         CF_USE1|CF_CHG2                 },      // Store
{ "sr",         CF_USE1|CF_USE2|CF_CHG2         },      // Store to auxiliary register
{ "flag",       CF_USE1                         },      // Set flags
{ "asr",        CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift right
{ "lsr",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical shift right
{ "sexb",       CF_CHG1|CF_USE2                 },      // Sign extend byte
{ "sexw",       CF_CHG1|CF_USE2                 },      // Sign extend word
{ "extb",       CF_CHG1|CF_USE2                 },      // Zero extend byte
{ "extw",       CF_CHG1|CF_USE2                 },      // Zero extend word
{ "ror",        CF_CHG1|CF_USE2|CF_USE3         },      // Rotate right
{ "rrc",        CF_CHG1|CF_USE2                 },      // Rotate right through carry
{ "b",          CF_USE1|CF_JUMP                 },      // Branch
{ "bl",         CF_USE1|CF_CALL                 },      // Branch and link
{ "lp",         CF_USE1                         },      // Zero-overhead loop setup
{ "j",          CF_USE1|CF_JUMP                 },      // Jump
{ "jl",         CF_USE1|CF_CALL                 },      // Jump and link
{ "add",        CF_CHG1|CF_USE2|CF_USE3         },      // Add
{ "adc",        CF_CHG1|CF_USE2|CF_USE3         },      // Add with carry
{ "sub",        CF_CHG1|CF_USE2|CF_USE3         },      // Subtract
{ "sbc",        CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with carry
{ "and",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise AND
{ "or",         CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise OR
{ "bic",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise AND with invert
{ "xor",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise exclusive-OR
{ "mov",        CF_CHG1|CF_USE2                 },      // Move
{ "nop",        0                               },      // No operation
{ "lsl",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical shift left
{ "rlc",        CF_CHG1|CF_USE2                 },      // Rotate left through carry
{ "brk",        0                               },      // Breakpoint
{ "sleep",      0                               },      // Sleep until interrupt or restart
{ "swi",        0                               },      // Software interrupt
{ "asl",        CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift left
{ "mul64",      CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply
{ "mulu64",     CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply
{ "max",        CF_CHG1|CF_USE2|CF_USE3         },      // Maximum of two signed integers
{ "min",        CF_CHG1|CF_USE2|CF_USE3         },      // Minimum of two signed integers
{ "swap",       CF_CHG1|CF_USE2                 },      // Exchange upper and lower 16 bits
{ "norm",       CF_CHG1|CF_USE2                 },      // Normalize (find-first-bit)

// ARCompact instructions
{ "bbit0",      CF_USE1|CF_USE2|CF_USE3         },      // Branch if bit cleared to 0
{ "bbit1",      CF_USE1|CF_USE2|CF_USE3         },      // Branch if bit set to 1
{ "br",         CF_USE1|CF_USE2|CF_USE3         },      // Branch on compare
{ "pop",        CF_CHG1                         },      // Restore register value from stack
{ "push",       CF_USE1                         },      // Store register value on stack

{ "abs",        CF_CHG1|CF_USE2                 },      // Absolute value
{ "add1",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 1 bit
{ "add2",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 2 bits
{ "add3",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 3 bits
{ "bclr",       CF_CHG1|CF_USE2|CF_USE3         },      // Clear specified bit (to 0)
{ "bmsk",       CF_CHG1|CF_USE2|CF_USE3         },      // Bit Mask
{ "bset",       CF_CHG1|CF_USE2|CF_USE3         },      // Set specified bit (to 1)
{ "btst",       CF_USE1|CF_USE2                 },      // Test value of specified bit
{ "bxor",       CF_CHG1|CF_USE2|CF_USE3         },      // Bit XOR
{ "cmp",        CF_USE1|CF_USE2                 },      // Compare
{ "ex",         CF_CHG1|CF_USE2                 },      // Atomic Exchange
{ "mpy",        CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply (low)
{ "mpyh",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply (high)
{ "mpyhu",      CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply (high)
{ "mpyu",       CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply (low)
{ "neg",        CF_CHG1|CF_USE2                 },      // Negate
{ "not",        CF_CHG1|CF_USE2                 },      // Logical bit inversion
{ "rcmp",       CF_USE1|CF_USE2                 },      // Reverse Compare
{ "rsub",       CF_CHG1|CF_USE2|CF_USE3         },      // Reverse Subtraction
{ "rtie",       0                               },      // Return from Interrupt/Exception
{ "sub1",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 1 bit
{ "sub2",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 2 bits
{ "sub3",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 3 bits
{ "sync",       0                               },      // Synchronize
{ "trap",       CF_USE1                         },      // Raise an exception
{ "tst",        CF_USE1|CF_USE2                 },      // Test
{ "unimp",      0                               },      // Unimplemented instruction

{ "abss",       CF_CHG1|CF_USE2                 },      // Absolute and saturate
{ "abssw",      CF_CHG1|CF_USE2                 },      // Absolute and saturate of word
{ "adds",       CF_CHG1|CF_USE2|CF_USE3         },      // Add and saturate
{ "addsdw",     CF_CHG1|CF_USE2|CF_USE3         },      // Add and saturate dual word
{ "asls",       CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift left and saturate
{ "asrs",       CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift right and saturate
{ "divaw",      CF_CHG1|CF_USE2|CF_USE3         },      // Division assist
{ "negs",       CF_CHG1|CF_USE2                 },      // Negate and saturate
{ "negsw",      CF_CHG1|CF_USE2                 },      // Negate and saturate of word
{ "normw",      CF_CHG1|CF_USE2                 },      // Normalize to 16 bits
{ "rnd16",      CF_CHG1|CF_USE2                 },      // Round to word
{ "sat16",      CF_CHG1|CF_USE2                 },      // Saturate to word
{ "subs",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract and saturate
{ "subsdw",     CF_CHG1|CF_USE2|CF_USE3         },      // Subtract and saturate dual word

{ "muldw",      CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "muludw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "mulrdw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "macdw",      CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "macudw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "macrdw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "msubdw",     CF_CHG1|CF_USE2|CF_USE3         },      // 

{ "mululw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "mullw",      CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "mulflw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "maclw",      CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "macflw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "machulw",    CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "machlw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "machflw",    CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "mulhlw",     CF_CHG1|CF_USE2|CF_USE3         },      // 
{ "mulhflw",    CF_CHG1|CF_USE2|CF_USE3         },      // 

};

CASSERT(qnumber(Instructions) == ARC_last);
