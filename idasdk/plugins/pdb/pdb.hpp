
#ifndef PDB__H
#define PDB__H

bool apply_debug_info(pdbargs_t &pdbargs);

#ifdef ENABLE_REMOTEPDB
bool is_win32_remote_debugger_loaded();
#endif

#include "pdbaccess.hpp"

#endif // PDB__H
