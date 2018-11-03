//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTIONS INFORMATIONS
//
//--------------------------------------------------------------------------


#include "deb_arm.hpp"

const char *arm_register_classes[] =
{
  "General registers",
  "VFP registers",
  // "FPU registerts",
  NULL
};


#ifndef __EA64__
static const char *const psr[] =
{
  "MODE",       // 0
  "MODE",       // 1
  "MODE",       // 2
  "MODE",       // 3
  "MODE",       // 4
  "T",          // 5
  "F",          // 6
  "I",          // 7
  "A",          // 8
  "E",          // 9
  "IT",         // 10
  "IT",         // 11
  "IT",         // 12
  "IT",         // 13
  "IT",         // 14
  "IT",         // 15
  "GE",         // 16
  "GE",         // 17
  "GE",         // 18
  "GE",         // 19
  NULL,         // 20
  NULL,         // 21
  NULL,         // 22
  NULL,         // 23
  "J",          // 24
  "IT2",        // 25 additional bits of IT
  "IT2",        // 26 additional bits of IT
  "Q",          // 27
  "V",          // 28
  "C",          // 29
  "Z",          // 30
  "N",          // 31
};

static const char *const vfp_format[] =
{
  "VFP_1_double",
};

register_info_t arm_registers[] =
{
  { "R0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R12",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "LR",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword, psr,    0xF800007F },

  /* Floating point registers ************************************************************/
  //{ "VFP0",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP1",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP2",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP3",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP4",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP5",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP6",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "VFP7",  0,                            ARM_RC_FPU,          dt_tbyte, NULL,   0 },
  //{ "SCR",   0,                            ARM_RC_FPU,          dt_word,  NULL,   0 },
  //{ "EXC",   0,                            ARM_RC_FPU,          dt_word,  NULL,   0 },
  /* VFP registers ***********************************************************************/
  { "D0",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D1",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D2",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D3",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D4",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D5",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D6",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D7",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D8",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D9",    REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D10",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D11",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D12",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D13",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D14",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D15",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D16",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D17",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D18",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D19",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D20",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D21",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D22",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D23",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D24",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D25",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D26",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D27",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D28",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D29",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D30",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "D31",   REGISTER_CUSTFMT, ARM_RC_VFP, dt_qword, vfp_format, 0 },
  { "FPSCR", 0,                ARM_RC_VFP, dt_dword, NULL,       0 },
};
#else

static const char *const psr[] =
{
  "M",          // 0 AArch32 mode that an exception was taken from
  "M",          // 1
  "M",          // 2
  "M",          // 3
  "M",          // 4 Execution state that the exception was taken from
  "T",          // 5 T32 Instruction set state bit
  "F",          // 6 FIQ mask bit
  "I",          // 7 IRQ mask bit
  "A",          // 8 Asynchronous data abort mask bit
  "E",          // 9 Endianness Execution State bit
  "IT",         // 10 If-Then
  "IT",         // 11
  "IT",         // 12
  "IT",         // 13
  "IT",         // 14
  "IT",         // 15
  "GE",         // 16 Greater than or Equal flags
  "GE",         // 17
  "GE",         // 18
  "GE",         // 19
  "IL",         // 20 Illegal Execution State bit
  NULL,         // 21
  NULL,         // 22
  NULL,         // 23
  NULL,         // 24
  "IT2",        // 25 If-Then
  "IT2",        // 26
  "Q",          // 27 Cumulative saturation bit
  "V",          // 28 oVerflow condition flag
  "C",          // 29 Carry condition flag
  "Z",          // 30 Zero condition flag
  "N",          // 31 Negative condition flag
};

register_info_t arm_registers[] =
{
  { "X0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X12",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X13",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X14",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X15",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X16",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X17",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X18",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X19",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X20",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X21",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X22",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X23",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X24",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X25",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X26",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X27",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X28",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X29",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "X30",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_qword, NULL,   0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword, psr, 0xF8000000 },
};
#endif
CASSERT(qnumber(arm_registers) == R_LAST);
