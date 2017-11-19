/*

  This is a reimplementation of the uunp universal unpacker in IDC.
  It illustrates the use of the new debugger functions in IDA v5.2

*/

#include <idc.idc>

//--------------------------------------------------------------------------
static main()
{
  auto ea, bptea, tea1, tea2, code, minea, maxea, r_esp, r_eip, caller, funcname;

  // Calculate the target IP range. It is the first segment.
  // As soon as the EIP register points to this range, we assume that
  // the unpacker has finished its work.
  tea1 = FirstSeg();
  tea2 = SegEnd(tea1);

  // Calculate the current module boundaries. Any calls to GetProcAddress
  // outside of these boundaries will be ignored.
  minea = MinEA();
  maxea = MaxEA();

  // Use win32 local debugger
  LoadDebugger("win32", 0);

  // Launch the debugger and run until the entry point
  if ( !RunTo(BeginEA()) )
    return Failed(-10);

  // Wait for the process to stop at the entry point
  code = GetDebuggerEvent(WFNE_SUSP, -1);
  if ( code <= 0 )
    return Failed(code);

  // Set a breakpoint at GetProcAddress
  bptea = LocByName("kernel32_GetProcAddress");
  if ( bptea == BADADDR )
    return Warning("Could not locate GetProcAddress");
  AddBpt(bptea);

  while ( 1 )
  {
    // resume the execution and wait until the unpacker calls GetProcAddress
    code = GetDebuggerEvent(WFNE_SUSP|WFNE_CONT, -1); // CONT means resume
    if ( code <= 0 )
      return Failed(code);

    // check the caller, it must be from our module
    r_esp = GetRegValue("ESP");
    caller = Dword(r_esp);
    if ( caller < minea || caller >= maxea )
      continue;

    // if the function name passed to GetProcAddress is not in the ignore-list,
    // then switch to the trace mode
    funcname = GetString(Dword(r_esp+8), -1, ASCSTR_C);
    // ignore some api calls because they might be used by the unpacker
    if ( funcname == "VirtualAlloc" )
      continue;
    if ( funcname == "VirtualFree" )
      continue;

    // A call to GetProcAddress() probably means that the program has been
    // unpacked in the memory and now is setting up its import table
    break;
  }

  // trace the program in the single step mode until we jump to
  // the area with the original entry point.
  DelBpt(bptea);
  EnableTracing(TRACE_STEP, 1);
  for ( code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1); // resume
        code > 0;
        code = GetDebuggerEvent(WFNE_ANY, -1) )
  {
    r_eip = GetEventEa();
    if ( r_eip >= tea1 && r_eip < tea2 )
      break;
  }
  if ( code <= 0 )
    return Failed(code);

  // as soon as the current ip belongs OEP area, suspend the execution and
  // inform the user
  PauseProcess();
  code = GetDebuggerEvent(WFNE_SUSP, -1);
  if ( code <= 0 )
    return Failed(code);

  EnableTracing(TRACE_STEP, 0);

  // Clean up the disassembly so it looks nicer
  MakeUnknown(tea1, tea2-tea1, DOUNK_EXPAND|DOUNK_DELNAMES);
  MakeCode(r_eip);
  AutoMark2(tea1, tea2, AU_USED);
  AutoMark2(tea1, tea2, AU_FINAL);
  TakeMemorySnapshot(1);
  MakeName(r_eip, "real_start");
  Warning("Successfully traced to the completion of the unpacker code\n"
          "Please rebuild the import table using renimp.idc\n"
          "before stopping the debugger");
}

//--------------------------------------------------------------------------
// Print an failure message
static Failed(code)
{
  Warning("Failed to unpack the file, sorry (code %d)", code);
  return 0;
}