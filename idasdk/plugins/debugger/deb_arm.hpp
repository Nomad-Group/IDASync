#ifndef __DEB_ARM__
#define __DEB_ARM__

#include <ua.hpp>
#include <idd.hpp>

#if defined(__LINUX__) && !defined(__ARMUCLINUX__) && defined(__ARM__) && !defined(__EA64__)
#define __HAVE_ARM_VFP__
#endif

#if (DEBUGGER_ID != DEBUGGER_ID_GDB_USER) && (DEBUGGER_ID != DEBUGGER_ID_TRACE_REPLAYER)
#define Eip Pc
#define Esp Sp
#endif

#define MEMORY_PAGE_SIZE 0x1000
//FIXME: #if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
// (The preprocessor defines are not propagated properly)
#ifdef UNDER_CE
#  define ARM_BPT_CODE    { 0x10, 0x00, 0x00, 0xE6 }    // wince bkpt
#else
#  define ARM_BPT_CODE    { 0xF0, 0x01, 0xF0, 0xE7 }    // und #10
#  define AARCH64_BPT_CODE  { 0x00, 0x00, 0x20, 0xD4 }  // brk #0
#endif

#define FPU_REGS_COUNT  8       // number of FPU registers
#define ARM_BPT_SIZE 4         // size of BPT instruction

#define ARM_T 20                // number of virtual T segment register in IDA
                                // it controls thumb/arm mode.

enum register_class_arm_t
{
  ARM_RC_GENERAL          = 0x01,
  ARM_RC_VFP              = 0x02,
  //ARM_RC_FPU              = 0x04,
#ifdef __HAVE_ARM_VFP__
  ARM_RC_ALL = ARM_RC_GENERAL | ARM_RC_VFP,
#else
  ARM_RC_ALL = ARM_RC_GENERAL,
#endif
};

// parallel arrays, must be edited together: arm_debmod_t::get_regidx()
//                                           register_info_t arm_registers[]
enum register_arm_t
{
#ifndef __EA64__
  // general registers
  R_R0,
  R_R1,
  R_R2,
  R_R3,
  R_R4,
  R_R5,
  R_R6,
  R_R7,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_SP,
  R_LR,
  R_PC,
  R_PSR,
  /* FPU registers ************************/
  // R_VFP0,
  // R_VFP1,
  // R_VFP2,
  // R_VFP3,
  // R_VFP4,
  // R_VFP5,
  // R_VFP6,
  // R_VFP7,
  // R_SCR,
  // R_EXC,
  /* VFP registers ***********************/
  R_D0,
  R_D1,
  R_D2,
  R_D3,
  R_D4,
  R_D5,
  R_D6,
  R_D7,
  R_D8,
  R_D9,
  R_D10,
  R_D11,
  R_D12,
  R_D13,
  R_D14,
  R_D15,
  R_D16,
  R_D17,
  R_D18,
  R_D19,
  R_D20,
  R_D21,
  R_D22,
  R_D23,
  R_D24,
  R_D25,
  R_D26,
  R_D27,
  R_D28,
  R_D29,
  R_D30,
  R_D31,
  R_FPSCR,
#else
  R_R0,
  R_R1,
  R_R2,
  R_R3,
  R_R4,
  R_R5,
  R_R6,
  R_R7,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
  R_R16,
  R_R17,
  R_R18,
  R_R19,
  R_R20,
  R_R21,
  R_R22,
  R_R23,
  R_R24,
  R_R25,
  R_R26,
  R_R27,
  R_R28,
  R_R29,
  R_LR,
  R_SP,
  R_PC,
  R_PSR,
#endif
  R_LAST,
};

extern const char *arm_register_classes[];
extern register_info_t arm_registers[R_LAST];

int idaapi arm_read_registers(thid_t thread_id, int clsmask, regval_t *values);
int idaapi arm_write_register(thid_t thread_id, int reg_idx, const regval_t *value);
int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len);

#endif

