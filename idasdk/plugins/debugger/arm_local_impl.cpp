#include <set>

#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <srarea.hpp>
#include <segment.hpp>

#include "deb_arm.hpp"

#include "arm_regs.cpp"

//--------------------------------------------------------------------------
int idaapi arm_read_registers(thid_t thread_id, int clsmask, regval_t *values)
{
  return s_read_registers(thread_id, clsmask, values);
}

//--------------------------------------------------------------------------
int idaapi arm_write_register(thid_t thread_id, int regidx, const regval_t *value)
{
  return s_write_register(thread_id, regidx, value);
}

//--------------------------------------------------------------------------
int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type == BPT_SOFT )
  {
    if ( (ea & 1) != 0 )
      return BPT_BAD_ADDR;
  }
  else
  {
    if ( type != BPT_RDWR         // type is good?
      && type != BPT_WRITE
      && type != BPT_EXEC )
    {
      return BPT_BAD_TYPE;
    }

    if ( (ea & (len-1)) != 0 )    // alignment is good?
      return BPT_BAD_ALIGN;

    if ( !strneq(debugger.name, "wince", 5) )
    {
      warning("AUTOHIDE REGISTRY\n"
              "ARM hardware breakpoints are not supported yet");
      return BPT_BAD_LEN;
    }

    if ( len != 1 )
    {
      warning("AUTOHIDE REGISTRY\n"
              "xScale supports only 1 byte length hardware breakpoints");
      return BPT_BAD_LEN;
    }
  }
  return BPT_OK;
}

//--------------------------------------------------------------------------
// if bit0 is set, ensure that thumb mode
// if bit0 is clear, ensure that arm mode
static void handle_arm_thumb_modes(ea_t ea)
{
  bool should_be_thumb = (ea & 1) != 0;
  bool is_thumb = get_segreg(ea, ARM_T) != 0;
  if ( should_be_thumb != is_thumb )
  {
    int code = processor_t::loader + (should_be_thumb ? 0 : 1);
    ph.notify(processor_t::idp_notify(code), ea & ~1);
  }
}

//--------------------------------------------------------------------------
static easet_t pending_addresses;

static int idaapi dbg_callback(void *, int code, va_list)
{
  // we apply thumb/arm switches when the process is suspended.
  // it is quite late (normally we should do it as soon as the corresponding
  // segment is created) but i did not manage to make it work.
  // in the segm_added event the addresses are not enabled yet,
  // so switching modes fails.
  if ( code == dbg_suspend_process && !pending_addresses.empty() )
  {
    for ( easet_t::iterator p=pending_addresses.begin();
          p != pending_addresses.end();
          ++p )
    {
      handle_arm_thumb_modes(*p);
    }
    pending_addresses.clear();
  }
  return 0;
}

//--------------------------------------------------------------------------
// For ARM processors the low bit means 1-thumb, 0-arm mode.
// The following function goes over the address list and sets the mode
// in IDA database according to bit0. It also resets bit0 for all addresses.
void set_arm_thumb_modes(ea_t *addrs, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    ea_t ea = addrs[i];
    segment_t *s = getseg(ea);
    if ( s == NULL )
      pending_addresses.insert(ea);
    else
      handle_arm_thumb_modes(ea);

    addrs[i] = ea & ~1;
  }
}

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
  hook_to_notification_point(HT_DBG, dbg_callback, NULL);
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
  unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
  pending_addresses.clear();
}
