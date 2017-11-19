// $Id: idp.cpp,v 1.9 2000/11/06 22:11:16 jeremy Exp $
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
// IDA TMS320C1X processor module.
//     IDP module entry structure
//
#include "../idaidp.hpp"
#include "idp.hpp"
#include "tms320c1.hpp"
#include "ana.hpp"
#include "reg.hpp"
#include "out.hpp"
#include "ins.hpp"
#include "asms.hpp"
#include "emu.hpp"

//
// Kernel message handlers.
//
void tms320c1x_Init(void);
void tms320c1x_NewFile(void);

//
// Global variables used within this processor module.
//
sel_t tms320c1x_dpage0; // Data page 0 selector
sel_t tms320c1x_dpage1; // Data page 1 selector

//
// tms320c1x_Notify()
//
// [ This function is named in our processor_t.notify member ]
//
// This function is the entry point that is called to notify the processor
// module of an important event.
//
static int idaapi
tms320c1x_Notify(processor_t::idp_notify msgid, ...)
{
        va_list va;
        va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

        int code = invoke_callbacks(HT_IDP, msgid, va);
        if ( code ) return code;

        switch ( msgid ) {
        case processor_t::init:
                //
                // Initialize the processor module.
                //
                tms320c1x_Init();
                break;
        case processor_t::newfile:
                //
                // Prepare for decoding of the file that has just been
                // loaded.
                //
                tms320c1x_NewFile();
                break;
        default:
                break;
        }

//      va_end(va);

        return 1;
}

//
// tms320c1x_Init()
//
// Initialize the processor module.
//
// (Called from tms320c1x_Notify()).
//
void
tms320c1x_Init()
{
                //
                // Have the IDA kernel interpret the data within the virtual
                // address space in a big-endian manner.
                //
                inf.mf = 1;
}

//
// tms320c1x_NewFile()
//
// Make any preparations needed to interpret the file that has
// just been loaded.
//
// (Called from tms320c1x_Notify()).
//
void
tms320c1x_NewFile()
{
        ea_t      data_start;
        segment_t dpage0, dpage1;

        //
        // There are no known executable file formats for TMS320C1X executables.
        // Therefore, we will assume in this processor module that the user
        // has loaded a program ROM image into IDA.  This image lacks any
        // definitions for data RAM, so we must create an area in IDA's virtual
        // address space to represent this RAM, thus enabling us to make
        // and track cross-references made to data RAM by TMS320C1X instructions.
        //
        // The TMS320C1X accesses data RAM in two discrete ways, the first of
        // which has a major impact on the strategy we must use to represent
        // data RAM.
        //
        // The first kind of access occurs during the execution of instructions
        // with immediate address operands.  The 7-bit immediate address operand
        // is combined with the current data page pointer bit in the processor
        // status register to give an 8-bit final address.  We will simulate this
        // behavior by keeping track of the data page pointer bit from instruction
        // to instruction, in effect acting as though it were a segment register.
        // We will then treat the 7-bit immediate address operand in each
        // instruction as though it were an offset into one of two data RAM
        // segments, depending on the current value of the data page pointer bit.
        // To do this, we need to create and define those two data segments here.
        //
        // The second manner in which the TMS320C1X access data RAM is during the
        // execution of instructions with indirect address operands.  An indirect
        // address operand is one which identifies a location in data RAM
        // indirectly through the current value in one of the accumulator or
        // auxiliary registers.  These memory references are fully qualified
        // since all three of these registers are spacious enough to hold all
        // 8-bits of addressing information.  Therefore, we needn't do anything
        // special here to accomodate these instructions.
        //

        //
        // Find a suitable place in IDA's virtual address space to place
        // the TMS320C1X's data RAM.  Make sure it is aligned on a 16 byte
        // boundary.
        //
        data_start = freechunk(0, TMS320C1X_DATA_RAM_SIZE, 15);

        ////
        //// Create the first data segment, otherwise known as 'data page 0'.
        ////

        //
        // Define its start and ending virtual address.
        //
        dpage0.startEA = data_start;
        dpage0.endEA   = data_start + (TMS320C1X_DATA_RAM_SIZE / 2);
        //
        // Assign it a unique selector value.
        //
        dpage0.sel     = allocate_selector(dpage0.startEA >> 4);
        //
        // Let the kernel know that it is a DATA segment.
        //
        dpage0.type    = SEG_DATA;
        //
        // Create the segment in the address space.
        //
        add_segm_ex(&dpage0, "dp0", NULL, ADDSEG_OR_DIE);

        ////
        //// Create the second data segment, otherwise known as 'data page 1'.
        ////

        //
        // Define its start and ending virtual address.
        //
        dpage1.startEA = data_start + (TMS320C1X_DATA_RAM_SIZE / 2);
        dpage1.endEA   = data_start + TMS320C1X_DATA_RAM_SIZE;
        //
        // Assign it a unique selector value.
        //
        dpage1.sel     = allocate_selector(dpage1.startEA >> 4);
        //
        // Let the kernel know that it is a DATA segment.
        //
        dpage1.type    = SEG_DATA;
        //
        // Create the segment in the address space.
        //
        add_segm_ex(&dpage1, "dp1", NULL, ADDSEG_OR_DIE);

        //
        // Store the selectors of these two data segments in the global
        // variables tms320c1x_dpage0 and tms320c1x_dpage1.
        //
        tms320c1x_dpage0 = dpage0.sel;
        tms320c1x_dpage1 = dpage1.sel;
}


//
// Short supported processor names.
//
// [ This array is named in our processor_t.psnames member ]
//
static const char *const shnames[] = {
        "tms320c1x",
        NULL
};

//
// Descriptive supported processor names.
//
// [ This array is named in our processor_t.plnames member ]
//
#define FAMILY "TMS320C1X Series:"
static const char *const lnames[] = {
        FAMILY"Texas Instruments TMS320C1X DSP",
        NULL
};

//
// Array of opcode streams that represent a function return
// instruction.
//
// [ This array is named in our processor_t.retcodes member ]
//
const bytes_t tms320c1x_retCodes[] = {
        { 0, 0 }
};

//////////////////////////////////////////////////////////////////////////////
// PROCESSOR MODULE DEFINITION
//////////////////////////////////////////////////////////////////////////////
processor_t LPH =
{
        IDP_INTERFACE_VERSION, // version
        PLFM_TMS320C1X,        // processor id
                               //
                               // processor module capablilty flags:
                               //
        PR_RNAMESOK |          // A register name can be used to name a location
        PR_BINMEM |            // The module creates segments for binary files
        PR_SEGS,               // We'd like to use the segment register tracking
                               // features of IDA.
                               //
        16,                    // Bits in a byte for code segments
        16,                    // Bits in a byte for other segments
        shnames,               // Array of short processor names
                               // the short names are used to specify the processor
                               // with the -p command line switch)
        lnames,                // array of long processor names
                               // the long names are used to build the processor
                               // selection menu type
        tms320c1x_Assemblers,  // array of target assemblers

        tms320c1x_Notify,      // Callback function for kernel event notification

        outHeader,             // the disassembly header generator function
        outFooter,             // the disassembly footer generator function

        outSegStart,           // generate a segment declaration (start of segment)
        std_gen_segm_footer,   // generate a segment footer (end of segment)

        NULL,                  // generate 'assume' directives

        ana,                   // analyze an instruction and fill the 'cmd' struct
        emu,                   // emulate an instruction

        out,                   // generate a text representation of an instruction
        outOp,                 // generate a text representation of an operand
        intel_data,            // generate a text representation of a data item
        NULL,                  // compare operands
        NULL,                  // can an operand have a type?

        nregisterNames,        // Number of registers
        registerNames,         // Regsiter names
        NULL,                  // get abstract register

        0,                     // Number of register files
        NULL,                  // Register file names
        NULL,                  // Register descriptions
        NULL,                  // Pointer to CPU registers

        IREG_VCS,              // First segment-register number
        IREG_VDS,              // Last segment-register number
        1,                     // size of a segment register
        IREG_VCS,              // CS segment-register number
        IREG_VDS,              // DS segment-register number

        NULL,                  // Known code start sequences
        tms320c1x_retCodes,    // Known return opcodes

        I__FIRST,             // First instruction number
        I__LAST,              // Last instruction number
        Instructions          // Array of instruction codes and features
};
