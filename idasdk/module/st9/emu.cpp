
#include "st9.hpp"

static bool flow;

//----------------------------------------------------------------------
// Emulate an operand.
static void handle_operand(const insn_t &insn, const op_t &op, bool lwrite)
{
  switch ( op.type )
  {
    // Code address
    case o_near:
      {
        cref_t mode;
        ea_t ea = to_ea(insn.cs, op.addr);

        // call or jump ?
        if ( insn.itype == st9_call || insn.itype == st9_calls )
        {
          if ( !func_does_return(ea) )
            flow = false;
          mode = fl_CN;
        }
        else
        {
          mode = fl_JN;
        }
        insn.add_cref(ea, op.offb, mode);
      }
      break;

    // Memory address
    case o_mem:
      insn.add_dref(to_ea(insn.cs, op.addr), op.offb, lwrite ? dr_W: dr_R);
      insn.create_op_data(op.addr, op);
      break;

    // Immediate value
    case o_imm:
      {
        set_immd(insn.ea);
        flags_t F = get_flags(insn.ea);
        // create a comment if this immediate is represented in the .cfg file
        {
          const ioport_t * port = find_sym(op.value);
          if ( port != NULL && !has_cmt(F) )
            set_cmt(insn.ea, port->cmt.c_str(), false);
        }
        // if the value was converted to an offset, then create a data xref:
        if ( op_adds_xrefs(F, op.n) )
          insn.add_off_drefs(op, dr_O, 0);
      }
      break;

    // Displacement
    case o_displ:
      {
        set_immd(insn.ea);
        flags_t F = get_flags(insn.ea);
        if ( op_adds_xrefs(F, op.n) )
        {
          ea_t ea = insn.add_off_drefs(op, dr_O, OOF_ADDR);
          insn.create_op_data(ea, op);
        }

        // create stack variables if required
        if ( may_create_stkvars() && !is_defarg(F, op.n) )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != NULL && pfn->flags & FUNC_FRAME )
          {
            if ( insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE) )
            {
              op_stkvar(insn.ea, op.n);
              if ( insn.Op2.type == o_reg )
              {
                regvar_t *r = find_regvar(pfn, insn.ea, ph.reg_names[insn.Op2.reg]);
                if ( r != NULL )
                {
                  struc_t *s = get_frame(pfn);
                  member_t *m = get_stkvar(NULL, insn, op, op.addr);
                  if ( s != NULL && m != NULL )
                  {
                    char b[20];
                    qsnprintf(b, sizeof b, "%scopy", r->user);
                    set_member_name(s, m->soff, b);
                  }
                }
              }
            }
          }
        }
      }
      break;

    // Register - Phrase - Void: do nothing
    case o_reg:
    case o_phrase:
    case o_void:
      break;

    default:
      INTERR(10076);
  }
}

//----------------------------------------------------------------------
// Emulate an instruction.
int idaapi st9_emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature();
  flow = ((feature & CF_STOP) == 0);

  if ( insn.Op1.type != o_void) handle_operand(insn, insn.Op1, (feature & CF_CHG1) != 0);
  if ( insn.Op2.type != o_void) handle_operand(insn, insn.Op2, (feature & CF_CHG2) != 0);
  if ( insn.Op3.type != o_void) handle_operand(insn, insn.Op3, (feature & CF_CHG3) != 0);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  //  Following code will update the current value of the two virtual
  //  segment registers: RW (register window) and RP (register page).

  bool rw_has_changed = false;
  bool rp_has_changed = false;

  switch ( insn.itype )
  {
    case st9_srp:
      {
        sel_t val = insn.Op1.value;
        if ( val % 2 )
          val--;     // even reduced
        split_sreg_range(insn.ea, rRW, val | (val << 8), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_srp0:
      {
        sel_t RW = get_sreg(insn.ea, rRW);
        split_sreg_range(insn.ea, rRW, insn.Op1.value | (RW & 0xFF00), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_srp1:
      {
        sel_t RW = get_sreg(insn.ea, rRW);
        split_sreg_range(insn.ea, rRW, (insn.Op1.value << 8) | (RW & 0x00FF), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_spp:
      split_sreg_range(insn.ea, rRP, insn.Op1.value, SR_auto);
      rp_has_changed = true;
      break;
  }

  // If RW / RP registers have changed, print a comment which explains the new mapping of
  // the general registers.

  flags_t F = get_flags(insn.ea);
  if ( rw_has_changed && !has_cmt(F) )
  {
    char buf[MAXSTR];
    sel_t RW = get_sreg(insn.ea, rRW);
    int low = RW & 0x00FF;
    int high = (RW & 0xFF00) >> 8;

    low *= 8;
    high *= 8;

    const char *const fmt =
      "r0 -> R%d, r1 -> R%d, r2 -> R%d, r3 -> R%d, r4 -> R%d, r5 -> R%d, r6 -> R%d, r7 -> R%d,\n"
      "r8 -> R%d, r9 -> R%d, r10 -> R%d, r11 -> R%d, r12 -> R%d, r13 -> R%d, r14 -> R%d, r15 -> R%d";

    qsnprintf(buf, sizeof buf, fmt,
        0 + low,
        1 + low,
        2 + low,
        3 + low,
        4 + low,
        5 + low,
        6 + low,
        7 + low,
        8 + high,
        9 + high,
        10 + high,
        11 + high,
        12 + high,
        13 + high,
        14 + high,
        15 + high);

    set_cmt(insn.ea, buf, false);
  }

  if ( rp_has_changed && !has_cmt(F) )
  {
    char buf[MAXSTR];
    qsnprintf(buf, sizeof buf, "Registers R240-R255 will now be referred to the page %d of paged registers",
              int(get_sreg(insn.ea, rRP)));
    set_cmt(insn.ea, buf, false);
  }

  return 1;
}

//----------------------------------------------------------------------
// Analyze an instruction
static ea_t next_insn(insn_t *insn, ea_t ea)
{
  if ( decode_insn(insn, ea) == 0 )
    return 0;
  ea += insn->size;
  return ea;
}

//----------------------------------------------------------------------
// Create a function frame
bool idaapi create_func_frame(func_t *pfn)
{
  ea_t ea = pfn->start_ea;

  insn_t insn;
  ea = next_insn(&insn, ea);
  if ( !ea )
    return 0;

  /*
   * Get the total frame size
   *
   * LINK rr14, #size
   */

  if ( insn.itype != st9_link )
    return 0;

  int link_register = insn.Op1.reg;
  size_t total_size = (size_t)insn.Op2.value;

  /*
   * Get arguments size
   *
   * LDW 0x??(rr14), RR???        a word
   * LD  ''                       a byte
   */

  int args_size = 0;

  for ( int i = 0; true; i++ )
  {
    insn_t ldi;
    ea = next_insn(&ldi, ea);
    if ( !ea )
      return 0;

    if ( ldi.Op1.type != o_displ || ldi.Op2.type != o_reg )
      break;

    if ( ldi.Op1.reg != link_register )
      break;

    if ( ldi.itype == st9_ld ) // byte
      args_size++;
    else if ( ldi.itype == st9_ldw ) // word
      args_size += 2;
    else
      break;

    char regvar[10];
    qsnprintf(regvar, sizeof regvar, "arg_%d", i);
    int err = add_regvar(pfn, ldi.ea, ldi.ea + ldi.size,
                         ph.reg_names[ldi.Op2.reg], regvar, NULL);
    if ( err )
      msg("add_regvar() failed : error %d\n", err);
  }

  /*
   * Detect FAR functions.
   */

  bool is_func_far = false;

  while ( true )
  {
    insn_t reti;
    ea = next_insn(&reti, ea);
    if ( ea == 0 )
      return 0;

    bool should_break = false;

    switch ( reti.itype )
    {
      case st9_ret:
      case st9_iret:
      case st9_eret:
        should_break = true;
        break;

      case st9_rets:
        is_func_far = should_break = true;
        break;
    }

    if ( should_break )
      break;
  }

  // mark the function as FAR
  if ( is_func_far )
    pfn->flags |= FUNC_FAR;

  //msg("LOCAL: %d\nARGS: %d\n", total_size - args_size, args_size);

  pfn->flags |= FUNC_FRAME;
  return add_frame(pfn, total_size - args_size, 0, args_size);
}
