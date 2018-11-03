/*
 *  This is a sample plugin module
 *
 *  It extends the IBM PC processor module to disassemble some NEC V20 instructions
 *
 *  This is a sample file, it supports just two instructions!
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static ea_t ea; // current address within the instruction

// Some definitions from IBM PC:

#define segrg specval_shorts.high  // IBM PC expects the segment address
                                   // to be here
#define aux_short       0x0020  // short (byte) displacement used
#define aux_basess      0x0200  // SS based instruction

#define R_ss  18
#define R_ds  19
//--------------------------------------------------------------------------
// This plugin supports just 2 instructions:
// Feel free to add more...

// 0FH 20H                      ADD4S                                ; Addition for packed BCD strings
// 0FH 12H Postbyte     CLEAR1  reg/mem8,CL                          ; Clear one bit

enum nec_insn_type_t
{
  NEC_add4s = CUSTOM_INSN_ITYPE,
  NEC_clear1,
};

//----------------------------------------------------------------------
static int get_dataseg(insn_t &insn, int defseg)
{
  if ( defseg == R_ss )
    insn.auxpref |= aux_basess;
  return defseg;
}

//--------------------------------------------------------------------------
//
//              process r/m byte of the instruction
//
static void process_rm(insn_t &insn, op_t &x, uchar postbyte)
{
  int Mod = (postbyte >> 6) & 3;
  x.reg = postbyte & 7;
  if ( Mod == 3 )               // register
  {
    if ( x.dtype == dt_byte )
      x.reg += 8;
    x.type = o_reg;
  }
  else                          // memory
  {
    if ( Mod == 0 && x.reg == 6 )
    {
      x.type = o_mem;
      x.offb = uchar(ea-insn.ea);
      x.addr = get_word(ea); ea+=2;
      x.segrg = (uint16)get_dataseg(insn, R_ds);
    }
    else
    {
      x.type = o_phrase;      // See reg for phrase
      x.addr = 0;
      x.segrg = (uint16)get_dataseg(insn, (x.phrase == 2 || x.phrase == 3 || x.phrase == 6) ? R_ss : R_ds);
                              // [bp+si],[bp+di],[bp] by SS
      if ( Mod != 0 )
      {
        x.type = o_displ;     // i.e. phrase + offset
        x.offb = uchar(ea-insn.ea);
        if ( Mod == 1 )
        {
          x.addr = char(get_byte(ea++));
          insn.auxpref |= aux_short;
        }
        else
        {
          x.addr = get_word(ea); ea+=2;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Analyze an instruction and fill the 'insn' structure
size_t ana(insn_t &insn)
{
  int code = get_byte(ea++);
  if ( code != 0x0F )
    return 0;
  code = get_byte(ea++);
  switch ( code )
  {
    case 0x20:
      insn.itype = NEC_add4s;
      return 2;
    case 0x12:
      insn.itype = NEC_clear1;
      {
        uchar postbyte = get_byte(ea++);
        process_rm(insn, insn.Op1, postbyte);
        insn.Op2.type = o_reg;
        insn.Op2.reg  = 9; // 9 is CL for IBM PC
        return size_t(ea - insn.ea);
      }
    default:
      return 0;
  }
}

//--------------------------------------------------------------------------
// Return the instruction mnemonics
const char *get_insn_mnem(const insn_t &insn)
{
  if ( insn.itype == NEC_add4s )
    return "add4s";
  return "clear1";
}

//--------------------------------------------------------------------------
// This callback is called for IDP (processor module) notification events
// Here we extend the processor module to disassemble opcode 0x0F
// (This is a hypothetical example)
// There are 2 approaches for the extensions:
//  A. Quick & dirty
//       you implemented ana_insn and out_insn
//       The first checks if the instruction is valid
//       The second generates its text
//  B. Thourough and clean
//       you implement all callbacks
//       ana_insn fills the 'insn' structure
//       emu_insn creates all xrefs using ua_add_[cd]ref functions
//       out_insn generates the instruction representation
//         (only if the instruction requires special processing
//          or the processor module can't handle the custom instruction for any reason)
//       out_operand generates the operand representation (only if the operand requires special processing)
//       out_mnem generates the instruction mnemonics
// The main difference between these 2 approaches is in the presence of cross-references
// and the amount of special processing required by the new instructions

// The quick & dirty approach
// We just produce the instruction mnemonics along with its operands
// No cross-references are created. No special processing.
static ssize_t idaapi dirty_extension_callback(void * /*user_data*/, int event_id, va_list va)
{
  switch ( event_id )
  {
    case processor_t::ev_ana_insn:
      {
        insn_t *insn = va_arg(va, insn_t *);
        ea = insn->ea;
        size_t length = ana(*insn);
        if ( length )
        {
          insn->size = (uint16)length;
          return insn->size;       // event processed
        }
      }
      break;
    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const insn_t &insn = ctx->insn;
        if ( insn.itype >= CUSTOM_INSN_ITYPE )
        {
          ctx->out_line(get_insn_mnem(insn), COLOR_INSN);
          return 1;
        }
      }
      break;
  }
  return 0;                     // event is not processed
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLUGIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the processor type and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//

static bool hooked = false;
static netnode nec_node;
static const char node_name[] = "$ sample NEC processor extender parameters";

int idaapi init(void)
{
  if ( ph.id != PLFM_386 )
    return PLUGIN_SKIP;
  nec_node.create(node_name);
  hooked = nec_node.altval(0) != 0;
  if ( hooked )
  {
    hook_to_notification_point(HT_IDP, dirty_extension_callback);
    msg("NEC V20 processor extender is enabled\n");
    return PLUGIN_KEEP;
  }
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, dirty_extension_callback);
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

bool idaapi run(size_t)
{
  if ( hooked )
    unhook_from_notification_point(HT_IDP, dirty_extension_callback);
  else
    hook_to_notification_point(HT_IDP, dirty_extension_callback);
  hooked = !hooked;
  nec_node.create(node_name);
  nec_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "NEC V20 processor extender now is %s", hooked ? "enabled" : "disabled");
  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "NEC V20 processor extender";
static const char help[] =
  "A sample plugin module\n"
  "\n"
  "This module shows you how to create plugin modules.\n"
  "\n"
  "It supports some NEC V20 instructions\n"
  "and shows the current address.\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

static const char wanted_name[] = "NEC V20 processor extender";

// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

static const char wanted_hotkey[] = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
