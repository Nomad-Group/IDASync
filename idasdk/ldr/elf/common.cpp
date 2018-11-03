/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      ELF binary loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include <idp.hpp>

#include "elfbase.h"


bool unpatched;

#ifndef _LOADER_HPP
#define loader_failure() qexit(1)
#endif

#ifndef NO_ERRSTRUCT
//--------------------------------------------------------------------------
#ifdef BUILD_LOADER
static void ask_for_exit(const char *str)
{
  if ( ask_yn(ASKBTN_YES, "HIDECANCEL\n%s. Continue?", str) <= ASKBTN_NO )
    loader_failure();
}

//-------------------------------------------------------------------------
static void ask_for_exit_once(const char *str)
{
  static qstrvec_t asked;
  if ( asked.has(str) )
    return;
  ask_for_exit(str);
  asked.push_back(str);
}
#endif // BUILD_EFD

//--------------------------------------------------------------------------
#if defined(BUILD_LOADER) || defined(EFD_COMPILE)
static void _errstruct(int line)
{
  static bool asked = false;
  if ( !asked )
  {
    if ( ask_yn(ASKBTN_YES,
                "HIDECANCEL\n"
                "Bad file structure or read error (line %d). Continue?",
                line) <= ASKBTN_NO )
    {
      loader_failure();
    }
    asked = true;
  }
}
#endif

#define errstruct() _errstruct(__LINE__)
#endif

//--------------------------------------------------------------------------
NORETURN inline void errnomem(void) { nomem("ELF"); }

//--------------------------------------------------------------------------
//      Functions common for EFD & DEBUGGER
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
static bool dummy_error_handler(const reader_t &, reader_t::errcode_t, ...)
{
  // ignore all errors
  return true;
}

//--------------------------------------------------------------------------
bool is_elf_file(linput_t *li)
{
  reader_t reader(li);
  reader.set_handler(dummy_error_handler);
  return reader.read_ident() && reader.read_header();
}


//--------------------------------------------------------------------------
int elf_machine_2_proc_module_id(reader_t &reader)
{
  int id = -1;
  switch ( reader.get_header().e_machine )
  {
#define CASE(E_ID, P_ID) case EM_##E_ID: id = PLFM_##P_ID; break
    CASE(ARM, ARM);
    CASE(SH, SH);
    CASE(PPC, PPC);
    CASE(PPC64, PPC);
    CASE(860, I860);
    CASE(68K, 68K);
    CASE(MIPS, MIPS);
    CASE(CISCO7200, MIPS);
    CASE(CISCO3620, MIPS);
    CASE(386, 386);
    CASE(486, 386);
    CASE(X86_64, 386);
    CASE(SPARC, SPARC);
    CASE(SPARC32PLUS, SPARC);
    CASE(SPARC64, SPARC);
    CASE(ALPHA, ALPHA);
    CASE(IA64, IA64);
    CASE(H8300, H8);
    CASE(H8300H, H8);
    CASE(H8S, H8);
    CASE(H8500, H8);
    CASE(V850, NEC_V850X);
    CASE(NECV850, NEC_V850X);
    CASE(PARISC, HPPA);
    CASE(6811, 6800);
    CASE(6812, MC6812);
    CASE(I960, I960);
    CASE(ARC, ARC);
    CASE(ARCOMPACT, ARC);
    CASE(ARC_COMPACT2, ARC);
    CASE(M32R, M32R);
    CASE(ST9, ST9);
    CASE(FR, FR);
    CASE(AVR, AVR);
    CASE(SPU, SPU);
    CASE(C166, C166);
    CASE(M16C, M16C);
    CASE(MN10200, MN102L00);
    // CASE(MN10300, MN103L00); // FIXME: Dunno what to do, here.
    // CASE(MCORE, MCORE); // FIXME: PLFM_MCORE still defined in mcore/reg.cpp
#undef CASE
  }
  return id;
}


