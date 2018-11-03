
#include "../../ldr/mach-o/macho_node.h"

//--------------------------------------------------------------------------
static bool rebase_scattered_segments(ea_t base)
{
  netnode node;
  node.create(MACHO_NODE);

  // detect if the code and data segments have moved relative to each other.
  // if so, we cannot simply apply a uniform delta to the entire database.
  // we must rebase one segment at a time.
  ea_t ldr_data = 0;
  ea_t ldr_text = 0;

  if ( node.hashval("__DATA", &ldr_data, sizeof(ldr_data), SEGM_TAG) == -1
    || node.hashval("__TEXT", &ldr_text, sizeof(ldr_text), SEGM_TAG) == -1 )
  {
    return false;
  }

  ea_t dbg_data = g_dbgmod.dbg_get_segm_start(base, "__DATA");
  ea_t dbg_text = g_dbgmod.dbg_get_segm_start(base, "__TEXT");

  if ( dbg_data == BADADDR || dbg_text == BADADDR )
    return false;

  adiff_t slide = (dbg_data - dbg_text) - (ldr_data - ldr_text);

  if ( slide == 0 )
    return false;

  scattered_image_t si;
  // we have detected segment scattering.
  // ensure that we can collect the vmaddr for each loader segment in IDA.
  if ( g_dbgmod.dbg_get_scattered_image(si, base) <= 0 )
    return false;

  uint8 ubuf[16];
  bytevec_t uuid;
  // it is quite possible that the input file does not match the image in the cache.
  // if there is a mismatch we warn the user.
  if ( !g_dbgmod.dbg_get_image_uuid(&uuid, base)
    || uuid.size() != sizeof(ubuf)
    || node.supval(MACHO_ALT_UUID, ubuf, sizeof(ubuf)) <= 0
    || memcmp(uuid.begin(), ubuf, sizeof(ubuf)) != 0 )
  {
    warning("AUTOHIDE DATABASE\n"
            "UUID mismatch between the input file and the image in memory.\n"
            "\n"
            "This could mean your dyld_shared_cache is out of sync with the library on disk,\n"
            "and the database will likely not be rebased properly.\n"
            "\n"
            "To ensure proper rebasing, please confirm that the input file was included\n"
            "the last time update_dyld_shared_cache was run.\n");
  }

  // adjust any pointers between the code and data segments
  show_wait_box("Rebasing CODE -> DATA pointers");
  // we want to patch pointers in the database without writing to debugger memory
  lock_dbgmem_config();

  for ( nodeidx_t nidx = node.charfirst(CODE_TAG);
        nidx != BADNODE && !user_cancelled();
        nidx = node.charnext(nidx, CODE_TAG) )
  {
    ea_t ea = node2ea(nidx);
    uchar kind = node.charval_ea(ea, CODE_TAG);
    switch ( kind )
    {
      case 1:  // 32-bit pointer
        add_dword(ea, slide);
        break;
      case 2:  // 64-bit pointer
        add_qword(ea, slide);
        break;
      default: // TODO: there are many more. we will deal with them later
        break;
    }
  }

  replace_wait_box("Rebasing DATA -> CODE pointers");

  for ( nodeidx_t nidx = node.charfirst(DATA_TAG);
        nidx != BADNODE && !user_cancelled();
        nidx = node.charnext(nidx, DATA_TAG) )
  {
    ea_t ea = node2ea(nidx);
    uchar kind = node.charval_ea(ea, DATA_TAG);
    switch ( kind )
    {
      case 1:  // pointer
        if ( inf.is_64bit() )
          add_qword(ea, -slide);
        else
          add_dword(ea, -slide);
        break;
      default: // TODO: there a few more. we will deal with them later
        break;
    }
  }

  hide_wait_box();
  unlock_dbgmem_config();

  qvector<segment_t *> ldrsegs;
  // we must collect all the loader segments before we start calling move_segm().
  // this is to avoid altering the areacb_t as we're iterating over it.
  for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->start_ea) )
  {
    if ( s->is_loader_segm() )
      ldrsegs.push_back(s);
  }

  show_wait_box("Rebasing scattered segments");

  bool ok = true;
  size_t ls_count = ldrsegs.size();
  size_t ss_count = si.size();

  // rebase each loader segment according to its matching segment in the scattered image.
  // currently we require the list of scattered segments and the list of loader segments
  // to have the exact same ordering. this is because we have no way to uniquely match a
  // loader segment and a scattered segment without some context. the segment's name, start_ea,
  // type, and selector are all not sufficient in this situation.
  for ( size_t i = 0; i < ls_count && !user_cancelled(); i++ )
  {
    segment_t *s = ldrsegs[i];

    qstring name;
    get_segm_name(&name, s);
    ea_t rebase_to = 0;

    if ( i < ss_count && name == si[i].name )
    {
      // found the loader segment in memory. rebase it to this address.
      rebase_to = si[i].start_ea;
    }
    else if ( name == "UNDEF" )
    {
      // UNDEF segment is not actually in memory. just rebase it along with the other data segments.
      rebase_to = s->start_ea + (dbg_data - ldr_data);
    }
    else
    {
      msg("%a: Failed to find segment %s in process memory!\n", s->start_ea, name.c_str());
      ok = false;
      break;
    }

    if ( s->start_ea != rebase_to )
    {
      replace_wait_box("Moving segment %s to %#a", name.c_str(), rebase_to);
      int code = move_segm(s, rebase_to, MSF_PRIORITY|MSF_SILENT);
      if ( code != MOVE_SEGM_OK )
      {
        msg("%a: Failed to rebase segment %s to %a, code=%d\n", s->start_ea, name.c_str(), rebase_to, code);
        ok = false;
      }
    }
  }

  hide_wait_box();
  set_imagebase(base);
  node.altset(MACHO_ALT_IMAGEBASE, base);

  // update segm eas in the database
  qstring idx;
  for ( ssize_t s = node.hashfirst(&idx, SEGM_TAG);
        s >= 0;
        s = node.hashnext(&idx, idx.c_str(), SEGM_TAG) )
  {
    ea_t start = g_dbgmod.dbg_get_segm_start(base, idx.c_str());
    if ( start != BADADDR )
      node.hashset(idx.c_str(), &start, sizeof(start), SEGM_TAG);
  }

  if ( !ok )
  {
    char buf[QMAXPATH];
    dbg_get_input_path(buf, sizeof(buf));
    warning("AUTOHIDE DATABASE\n"
            "Some loader segments were not rebased properly.\n"
            "\n"
            "This error might occur if you are debugging a dylib from /System/Library or /usr/lib,\n"
            "since these files have different segment info when they are loaded from dyld_shared_cache.\n"
            "\n"
            "To ensure more accurate segment info when debugging, you can:\n"
            "\n"
            "  1. open the dyld_shared_cache in IDA (usually found in /var/db/dyld/)\n"
            "  2. select the 'Apple DYLD cache (single module)' option\n"
            "  3. select %s from the list of modules\n"
            "  4. use %s as the input file path in the Process Options dialog\n", qbasename(buf), buf);
  }

  return true;
}
