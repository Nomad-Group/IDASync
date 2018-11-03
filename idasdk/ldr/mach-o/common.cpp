#include "../idaldr.h"
#include "common.h"
#include <range.hpp>
#include <kernwin.hpp>

#include "../ar/ar.hpp"

//--------------------------------------------------------------------------
bool isPair(const struct mach_header_64 *mh, int type)
{
   return (mh->cputype == CPU_TYPE_ARM     && type == ARM_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_MC680x0 && type == GENERIC_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_I386    && type == GENERIC_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_MC88000 && type == M88K_RELOC_PAIR)
       || ((mh->cputype == CPU_TYPE_POWERPC
         || mh->cputype == CPU_TYPE_POWERPC64
         || mh->cputype == CPU_TYPE_VEO)   && type == PPC_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_HPPA    && type == HPPA_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_SPARC   && type == SPARC_RELOC_PAIR)
       || (mh->cputype == CPU_TYPE_I860    && type == I860_RELOC_PAIR);
}

//--------------------------------------------------------------------------
bool isSectdiff(const struct mach_header_64 *mh, int type)
{
  return (mh->cputype == CPU_TYPE_MC680x0 && (type == GENERIC_RELOC_SECTDIFF || type == GENERIC_RELOC_LOCAL_SECTDIFF))
      || (mh->cputype == CPU_TYPE_I386 && (type == GENERIC_RELOC_SECTDIFF || type == GENERIC_RELOC_LOCAL_SECTDIFF))
      || (mh->cputype == CPU_TYPE_ARM
       && (type == ARM_RELOC_SECTDIFF
        || type == ARM_RELOC_LOCAL_SECTDIFF
        || type == ARM_RELOC_HALF_SECTDIFF))
      || (mh->cputype == CPU_TYPE_MC88000 && type == M88K_RELOC_SECTDIFF)
      || ((mh->cputype == CPU_TYPE_POWERPC
        || mh->cputype == CPU_TYPE_POWERPC64
        || mh->cputype == CPU_TYPE_VEO)
       && (type == PPC_RELOC_SECTDIFF
        || type == PPC_RELOC_LOCAL_SECTDIFF
        || type == PPC_RELOC_HI16_SECTDIFF
        || type == PPC_RELOC_LO16_SECTDIFF
        || type == PPC_RELOC_LO14_SECTDIFF
        || type == PPC_RELOC_HA16_SECTDIFF))
      || (mh->cputype == CPU_TYPE_I860 && type == I860_RELOC_SECTDIFF)
      || (mh->cputype == CPU_TYPE_HPPA
       && (type == HPPA_RELOC_SECTDIFF
        || type == HPPA_RELOC_HI21_SECTDIFF
        || type == HPPA_RELOC_LO14_SECTDIFF))
      || (mh->cputype == CPU_TYPE_SPARC
       && (type == SPARC_RELOC_SECTDIFF
        || type == SPARC_RELOC_HI22_SECTDIFF
        || type == SPARC_RELOC_LO10_SECTDIFF));
}

//--------------------------------------------------------------------------
local void swap_mach_header_64(struct mach_header_64 *mh)
{
  mh->magic      = swap32(mh->magic);
  mh->cputype    = swap32(mh->cputype);
  mh->cpusubtype = swap32(mh->cpusubtype);
  mh->filetype   = swap32(mh->filetype);
  mh->ncmds      = swap32(mh->ncmds);
  mh->sizeofcmds = swap32(mh->sizeofcmds);
  mh->flags      = swap32(mh->flags);
  mh->reserved   = swap32(mh->reserved);
}

//--------------------------------------------------------------------------
local void swap_load_command(load_command *lc)
{
        lc->cmd = swap32(lc->cmd);
        lc->cmdsize = swap32(lc->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_segment_command(segment_command *sg)
{
  /* segname[16] */
  sg->cmd = swap32(sg->cmd);
  sg->cmdsize = swap32(sg->cmdsize);
  sg->vmaddr = swap32(sg->vmaddr);
  sg->vmsize = swap32(sg->vmsize);
  sg->fileoff = swap32(sg->fileoff);
  sg->filesize = swap32(sg->filesize);
  sg->maxprot = swap32(sg->maxprot);
  sg->initprot = swap32(sg->initprot);
  sg->nsects = swap32(sg->nsects);
  sg->flags = swap32(sg->flags);
}

local void swap_segment_command(segment_command_64 *sg)
{
  /* segname[16] */
  sg->cmd = swap32(sg->cmd);
  sg->cmdsize = swap32(sg->cmdsize);
  sg->vmaddr = swap64(sg->vmaddr);
  sg->vmsize = swap64(sg->vmsize);
  sg->fileoff = swap64(sg->fileoff);
  sg->filesize = swap64(sg->filesize);
  sg->maxprot = swap32(sg->maxprot);
  sg->initprot = swap32(sg->initprot);
  sg->nsects = swap32(sg->nsects);
  sg->flags = swap32(sg->flags);
}

//--------------------------------------------------------------------------
local void swap_section(section *s, uint32 nsects)
{
  for ( uint32 i = 0; i < nsects; i++ )
  {
    /* sectname[16] */
    /* segname[16] */
    s[i].addr = swap32(s[i].addr);
    s[i].size = swap32(s[i].size);
    s[i].offset = swap32(s[i].offset);
    s[i].align = swap32(s[i].align);
    s[i].reloff = swap32(s[i].reloff);
    s[i].nreloc = swap32(s[i].nreloc);
    s[i].flags = swap32(s[i].flags);
    s[i].reserved1 = swap32(s[i].reserved1);
    s[i].reserved2 = swap32(s[i].reserved2);
  }
}

//--------------------------------------------------------------------------
local void swap_section(section_64 *s, uint32 nsects)
{
  for ( uint32 i = 0; i < nsects; i++ )
  {
    /* sectname[16] */
    /* segname[16] */
    s[i].addr = swap64(s[i].addr);
    s[i].size = swap64(s[i].size);
    s[i].offset = swap32(s[i].offset);
    s[i].align = swap32(s[i].align);
    s[i].reloff = swap32(s[i].reloff);
    s[i].nreloc = swap32(s[i].nreloc);
    s[i].flags = swap32(s[i].flags);
    s[i].reserved1 = swap32(s[i].reserved1);
    s[i].reserved2 = swap32(s[i].reserved2);
  }
}

//--------------------------------------------------------------------------
local void swap_symtab_command(symtab_command *st)
{
  st->cmd = swap32(st->cmd);
  st->cmdsize = swap32(st->cmdsize);
  st->symoff = swap32(st->symoff);
  st->nsyms = swap32(st->nsyms);
  st->stroff = swap32(st->stroff);
  st->strsize = swap32(st->strsize);
}

//--------------------------------------------------------------------------
local void swap_dysymtab_command(dysymtab_command *dyst)
{
  dyst->cmd = swap32(dyst->cmd);
  dyst->cmdsize = swap32(dyst->cmdsize);
  dyst->ilocalsym = swap32(dyst->ilocalsym);
  dyst->nlocalsym = swap32(dyst->nlocalsym);
  dyst->iextdefsym = swap32(dyst->iextdefsym);
  dyst->nextdefsym = swap32(dyst->nextdefsym);
  dyst->iundefsym = swap32(dyst->iundefsym);
  dyst->nundefsym = swap32(dyst->nundefsym);
  dyst->tocoff = swap32(dyst->tocoff);
  dyst->ntoc = swap32(dyst->ntoc);
  dyst->modtaboff = swap32(dyst->modtaboff);
  dyst->nmodtab = swap32(dyst->nmodtab);
  dyst->extrefsymoff = swap32(dyst->extrefsymoff);
  dyst->nextrefsyms = swap32(dyst->nextrefsyms);
  dyst->indirectsymoff = swap32(dyst->indirectsymoff);
  dyst->nindirectsyms = swap32(dyst->nindirectsyms);
  dyst->extreloff = swap32(dyst->extreloff);
  dyst->nextrel = swap32(dyst->nextrel);
  dyst->locreloff = swap32(dyst->locreloff);
  dyst->nlocrel = swap32(dyst->nlocrel);
}

//--------------------------------------------------------------------------
local void swap_symseg_command(symseg_command *ss)
{
  ss->cmd = swap32(ss->cmd);
  ss->cmdsize = swap32(ss->cmdsize);
  ss->offset = swap32(ss->offset);
  ss->size = swap32(ss->size);
}

//--------------------------------------------------------------------------
local void swap_fvmlib_command(fvmlib_command *fl)
{
  fl->cmd = swap32(fl->cmd);
  fl->cmdsize = swap32(fl->cmdsize);
  fl->fvmlib.name.offset = swap32(fl->fvmlib.name.offset);
  fl->fvmlib.minor_version = swap32(fl->fvmlib.minor_version);
  fl->fvmlib.header_addr = swap32(fl->fvmlib.header_addr);
}

//--------------------------------------------------------------------------
local void swap_thread_command(thread_command *tc)
{
  tc->cmd = swap32(tc->cmd);
  tc->cmdsize = swap32(tc->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_dylib_command(dylib_command *dl)
{
  dl->cmd = swap32(dl->cmd);
  dl->cmdsize = swap32(dl->cmdsize);
  dl->dylib.name.offset = swap32(dl->dylib.name.offset);
  dl->dylib.timestamp = swap32(dl->dylib.timestamp);
  dl->dylib.current_version = swap32(dl->dylib.current_version);
  dl->dylib.compatibility_version = swap32(dl->dylib.compatibility_version);
}

//--------------------------------------------------------------------------
local void swap_sub_framework_command(sub_framework_command *sub)
{
  sub->cmd = swap32(sub->cmd);
  sub->cmdsize = swap32(sub->cmdsize);
  sub->umbrella.offset = swap32(sub->umbrella.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_umbrella_command(sub_umbrella_command *usub)
{
  usub->cmd = swap32(usub->cmd);
  usub->cmdsize = swap32(usub->cmdsize);
  usub->sub_umbrella.offset = swap32(usub->sub_umbrella.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_library_command(struct sub_library_command *lsub)
{
  lsub->cmd = swap32(lsub->cmd);
  lsub->cmdsize = swap32(lsub->cmdsize);
  lsub->sub_library.offset = swap32(lsub->sub_library.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_client_command(sub_client_command *csub)
{
  csub->cmd = swap32(csub->cmd);
  csub->cmdsize = swap32(csub->cmdsize);
  csub->client.offset = swap32(csub->client.offset);
}

//--------------------------------------------------------------------------
local void swap_prebound_dylib_command(prebound_dylib_command *pbdylib)
{
  pbdylib->cmd = swap32(pbdylib->cmd);
  pbdylib->cmdsize = swap32(pbdylib->cmdsize);
  pbdylib->name.offset = swap32(pbdylib->name.offset);
  pbdylib->nmodules = swap32(pbdylib->nmodules);
  pbdylib->linked_modules.offset = swap32(pbdylib->linked_modules.offset);
}

//--------------------------------------------------------------------------
local void swap_dylinker_command(dylinker_command *dyld)
{
  dyld->cmd = swap32(dyld->cmd);
  dyld->cmdsize = swap32(dyld->cmdsize);
  dyld->name.offset = swap32(dyld->name.offset);
}

//--------------------------------------------------------------------------
local void swap_fvmfile_command(fvmfile_command *ff)
{
  ff->cmd = swap32(ff->cmd);
  ff->cmdsize = swap32(ff->cmdsize);
  ff->name.offset = swap32(ff->name.offset);
  ff->header_addr = swap32(ff->header_addr);
}

//--------------------------------------------------------------------------
/*
#ifndef EFD_COMPILE
local void swap_thread_command(thread_command *ut)
{
  ut->cmd = swap32(ut->cmd);
  ut->cmdsize = swap32(ut->cmdsize);
}
#endif // EFD_COMPILE
*/

//--------------------------------------------------------------------------
/*
local void swap_m68k_thread_state_regs(struct m68k_thread_state_regs *cpu)
{
  uint32 i;
  for ( i = 0; i < 8; i++ )
    cpu->dreg[i] = swap32(cpu->dreg[i]);
  for ( i = 0; i < 8; i++ )
    cpu->areg[i] = swap32(cpu->areg[i]);
  cpu->pad0 = swap16(cpu->pad0);
  cpu->sr = swap16(cpu->sr);
  cpu->pc = swap32(cpu->pc);
}

//--------------------------------------------------------------------------
local void swap_m68k_thread_state_68882(struct m68k_thread_state_68882 *fpu)
{
  uint32 i, tmp;

  for ( i = 0; i < 8; i++ )
  {
                   tmp = swap32(fpu->regs[i].fp[0]);
    fpu->regs[i].fp[1] = swap32(fpu->regs[i].fp[1]);
    fpu->regs[i].fp[0] = swap32(fpu->regs[i].fp[2]);
    fpu->regs[i].fp[2] = tmp;
  }
  fpu->cr = swap32(fpu->cr);
  fpu->sr = swap32(fpu->sr);
  fpu->iar = swap32(fpu->iar);
  fpu->state = swap32(fpu->state);
}

//--------------------------------------------------------------------------
local void swap_m68k_thread_state_user_reg(struct m68k_thread_state_user_reg *user_reg)
{
  user_reg->user_reg = swap32(user_reg->user_reg);
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_grf_t(m88k_thread_state_grf_t *cpu)
{
  cpu->r1 = swap32(cpu->r1);
  cpu->r2 = swap32(cpu->r2);
  cpu->r3 = swap32(cpu->r3);
  cpu->r4 = swap32(cpu->r4);
  cpu->r5 = swap32(cpu->r5);
  cpu->r6 = swap32(cpu->r6);
  cpu->r7 = swap32(cpu->r7);
  cpu->r8 = swap32(cpu->r8);
  cpu->r9 = swap32(cpu->r9);
  cpu->r10 = swap32(cpu->r10);
  cpu->r11 = swap32(cpu->r11);
  cpu->r12 = swap32(cpu->r12);
  cpu->r13 = swap32(cpu->r13);
  cpu->r14 = swap32(cpu->r14);
  cpu->r15 = swap32(cpu->r15);
  cpu->r16 = swap32(cpu->r16);
  cpu->r17 = swap32(cpu->r17);
  cpu->r18 = swap32(cpu->r18);
  cpu->r19 = swap32(cpu->r19);
  cpu->r20 = swap32(cpu->r20);
  cpu->r21 = swap32(cpu->r21);
  cpu->r22 = swap32(cpu->r22);
  cpu->r23 = swap32(cpu->r23);
  cpu->r24 = swap32(cpu->r24);
  cpu->r25 = swap32(cpu->r25);
  cpu->r26 = swap32(cpu->r26);
  cpu->r27 = swap32(cpu->r27);
  cpu->r28 = swap32(cpu->r28);
  cpu->r29 = swap32(cpu->r29);
  cpu->r30 = swap32(cpu->r30);
  cpu->r31 = swap32(cpu->r31);
  cpu->xip = swap32(cpu->xip);
  cpu->xip_in_bd = swap32(cpu->xip_in_bd);
  cpu->nip = swap32(cpu->nip);
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_xrf_t(m88k_thread_state_xrf_t *fpu)
{
  struct swapped_m88k_fpsr
  {
    union
    {
      struct
      {
        unsigned afinx:BIT_WIDTH(0);
        unsigned afovf:BIT_WIDTH(1);
        unsigned afunf:BIT_WIDTH(2);
        unsigned afdvz:BIT_WIDTH(3);
        unsigned afinv:BIT_WIDTH(4);
        unsigned      :BITS_WIDTH(15,5);
        unsigned xmod :BIT_WIDTH(16);
        unsigned      :BITS_WIDTH(31,17);
      } fields;
      uint32 word;
    } u;
  } ssr;
  struct swapped_m88k_fpcr
  {
    union
    {
      struct
      {
        unsigned efinx:BIT_WIDTH(0);
        unsigned efovf:BIT_WIDTH(1);
        unsigned efunf:BIT_WIDTH(2);
        unsigned efdvz:BIT_WIDTH(3);
        unsigned efinv:BIT_WIDTH(4);
        unsigned      :BITS_WIDTH(13,5);
        m88k_fpcr_rm_t rm:BITS_WIDTH(15,14);
        unsigned      :BITS_WIDTH(31,16);
      } fields;
      uint32 word;
    } u;
  } scr;

  fpu->x1.x[0] = swap32(fpu->x1.x[0]);
  fpu->x1.x[1] = swap32(fpu->x1.x[1]);
  fpu->x1.x[2] = swap32(fpu->x1.x[2]);
  fpu->x1.x[3] = swap32(fpu->x1.x[3]);
  fpu->x2.x[0] = swap32(fpu->x2.x[0]);
  fpu->x2.x[1] = swap32(fpu->x2.x[1]);
  fpu->x2.x[2] = swap32(fpu->x2.x[2]);
  fpu->x2.x[3] = swap32(fpu->x2.x[3]);
  fpu->x3.x[0] = swap32(fpu->x3.x[0]);
  fpu->x3.x[1] = swap32(fpu->x3.x[1]);
  fpu->x3.x[2] = swap32(fpu->x3.x[2]);
  fpu->x3.x[3] = swap32(fpu->x3.x[3]);
  fpu->x4.x[0] = swap32(fpu->x4.x[0]);
  fpu->x4.x[1] = swap32(fpu->x4.x[1]);
  fpu->x4.x[2] = swap32(fpu->x4.x[2]);
  fpu->x4.x[3] = swap32(fpu->x4.x[3]);
  fpu->x5.x[0] = swap32(fpu->x5.x[0]);
  fpu->x5.x[1] = swap32(fpu->x5.x[1]);
  fpu->x5.x[2] = swap32(fpu->x5.x[2]);
  fpu->x5.x[3] = swap32(fpu->x5.x[3]);
  fpu->x6.x[0] = swap32(fpu->x6.x[0]);
  fpu->x6.x[1] = swap32(fpu->x6.x[1]);
  fpu->x6.x[2] = swap32(fpu->x6.x[2]);
  fpu->x6.x[3] = swap32(fpu->x6.x[3]);
  fpu->x7.x[0] = swap32(fpu->x7.x[0]);
  fpu->x7.x[1] = swap32(fpu->x7.x[1]);
  fpu->x7.x[2] = swap32(fpu->x7.x[2]);
  fpu->x7.x[3] = swap32(fpu->x7.x[3]);
  fpu->x8.x[0] = swap32(fpu->x8.x[0]);
  fpu->x8.x[1] = swap32(fpu->x8.x[1]);
  fpu->x8.x[2] = swap32(fpu->x8.x[2]);
  fpu->x8.x[3] = swap32(fpu->x8.x[3]);
  fpu->x9.x[0] = swap32(fpu->x9.x[0]);
  fpu->x9.x[1] = swap32(fpu->x9.x[1]);
  fpu->x9.x[2] = swap32(fpu->x9.x[2]);
  fpu->x9.x[3] = swap32(fpu->x9.x[3]);
  fpu->x10.x[0] = swap32(fpu->x10.x[0]);
  fpu->x10.x[1] = swap32(fpu->x10.x[1]);
  fpu->x10.x[2] = swap32(fpu->x10.x[2]);
  fpu->x10.x[3] = swap32(fpu->x10.x[3]);
  fpu->x11.x[0] = swap32(fpu->x11.x[0]);
  fpu->x11.x[1] = swap32(fpu->x11.x[1]);
  fpu->x11.x[2] = swap32(fpu->x11.x[2]);
  fpu->x11.x[3] = swap32(fpu->x11.x[3]);
  fpu->x12.x[0] = swap32(fpu->x12.x[0]);
  fpu->x12.x[1] = swap32(fpu->x12.x[1]);
  fpu->x12.x[2] = swap32(fpu->x12.x[2]);
  fpu->x12.x[3] = swap32(fpu->x12.x[3]);
  fpu->x13.x[0] = swap32(fpu->x13.x[0]);
  fpu->x13.x[1] = swap32(fpu->x13.x[1]);
  fpu->x13.x[2] = swap32(fpu->x13.x[2]);
  fpu->x13.x[3] = swap32(fpu->x13.x[3]);
  fpu->x14.x[0] = swap32(fpu->x14.x[0]);
  fpu->x14.x[1] = swap32(fpu->x14.x[1]);
  fpu->x14.x[2] = swap32(fpu->x14.x[2]);
  fpu->x14.x[3] = swap32(fpu->x14.x[3]);
  fpu->x15.x[0] = swap32(fpu->x15.x[0]);
  fpu->x15.x[1] = swap32(fpu->x15.x[1]);
  fpu->x15.x[2] = swap32(fpu->x15.x[2]);
  fpu->x15.x[3] = swap32(fpu->x15.x[3]);
  fpu->x16.x[0] = swap32(fpu->x16.x[0]);
  fpu->x16.x[1] = swap32(fpu->x16.x[1]);
  fpu->x16.x[2] = swap32(fpu->x16.x[2]);
  fpu->x16.x[3] = swap32(fpu->x16.x[3]);
  fpu->x17.x[0] = swap32(fpu->x17.x[0]);
  fpu->x17.x[1] = swap32(fpu->x17.x[1]);
  fpu->x17.x[2] = swap32(fpu->x17.x[2]);
  fpu->x17.x[3] = swap32(fpu->x17.x[3]);
  fpu->x18.x[0] = swap32(fpu->x18.x[0]);
  fpu->x18.x[1] = swap32(fpu->x18.x[1]);
  fpu->x18.x[2] = swap32(fpu->x18.x[2]);
  fpu->x18.x[3] = swap32(fpu->x18.x[3]);
  fpu->x19.x[0] = swap32(fpu->x19.x[0]);
  fpu->x19.x[1] = swap32(fpu->x19.x[1]);
  fpu->x19.x[2] = swap32(fpu->x19.x[2]);
  fpu->x19.x[3] = swap32(fpu->x19.x[3]);
  fpu->x20.x[0] = swap32(fpu->x20.x[0]);
  fpu->x20.x[1] = swap32(fpu->x20.x[1]);
  fpu->x20.x[2] = swap32(fpu->x20.x[2]);
  fpu->x20.x[3] = swap32(fpu->x20.x[3]);
  fpu->x21.x[0] = swap32(fpu->x21.x[0]);
  fpu->x21.x[1] = swap32(fpu->x21.x[1]);
  fpu->x21.x[2] = swap32(fpu->x21.x[2]);
  fpu->x21.x[3] = swap32(fpu->x21.x[3]);
  fpu->x22.x[0] = swap32(fpu->x22.x[0]);
  fpu->x22.x[1] = swap32(fpu->x22.x[1]);
  fpu->x22.x[2] = swap32(fpu->x22.x[2]);
  fpu->x22.x[3] = swap32(fpu->x22.x[3]);
  fpu->x23.x[0] = swap32(fpu->x23.x[0]);
  fpu->x23.x[1] = swap32(fpu->x23.x[1]);
  fpu->x23.x[2] = swap32(fpu->x23.x[2]);
  fpu->x23.x[3] = swap32(fpu->x23.x[3]);
  fpu->x24.x[0] = swap32(fpu->x24.x[0]);
  fpu->x24.x[1] = swap32(fpu->x24.x[1]);
  fpu->x24.x[2] = swap32(fpu->x24.x[2]);
  fpu->x24.x[3] = swap32(fpu->x24.x[3]);
  fpu->x25.x[0] = swap32(fpu->x25.x[0]);
  fpu->x25.x[1] = swap32(fpu->x25.x[1]);
  fpu->x25.x[2] = swap32(fpu->x25.x[2]);
  fpu->x25.x[3] = swap32(fpu->x25.x[3]);
  fpu->x26.x[0] = swap32(fpu->x26.x[0]);
  fpu->x26.x[1] = swap32(fpu->x26.x[1]);
  fpu->x26.x[2] = swap32(fpu->x26.x[2]);
  fpu->x26.x[3] = swap32(fpu->x26.x[3]);
  fpu->x27.x[0] = swap32(fpu->x27.x[0]);
  fpu->x27.x[1] = swap32(fpu->x27.x[1]);
  fpu->x27.x[2] = swap32(fpu->x27.x[2]);
  fpu->x27.x[3] = swap32(fpu->x27.x[3]);
  fpu->x28.x[0] = swap32(fpu->x28.x[0]);
  fpu->x28.x[1] = swap32(fpu->x28.x[1]);
  fpu->x28.x[2] = swap32(fpu->x28.x[2]);
  fpu->x28.x[3] = swap32(fpu->x28.x[3]);
  fpu->x29.x[0] = swap32(fpu->x29.x[0]);
  fpu->x29.x[1] = swap32(fpu->x29.x[1]);
  fpu->x29.x[2] = swap32(fpu->x29.x[2]);
  fpu->x29.x[3] = swap32(fpu->x29.x[3]);
  fpu->x30.x[0] = swap32(fpu->x30.x[0]);
  fpu->x30.x[1] = swap32(fpu->x30.x[1]);
  fpu->x30.x[2] = swap32(fpu->x30.x[2]);
  fpu->x30.x[3] = swap32(fpu->x30.x[3]);
  fpu->x31.x[0] = swap32(fpu->x31.x[0]);
  fpu->x31.x[1] = swap32(fpu->x31.x[1]);
  fpu->x31.x[2] = swap32(fpu->x31.x[2]);
  fpu->x31.x[3] = swap32(fpu->x31.x[3]);

  if ( !mf )
  {
    memcpy(&ssr, &(fpu->fpsr), sizeof(struct swapped_m88k_fpsr));
    ssr.u.word = swap32(ssr.u.word);
    fpu->fpsr.afinx = ssr.u.fields.afinx;
    fpu->fpsr.afovf = ssr.u.fields.afovf;
    fpu->fpsr.afunf = ssr.u.fields.afunf;
    fpu->fpsr.afdvz = ssr.u.fields.afdvz;
    fpu->fpsr.afinv = ssr.u.fields.afinv;
    fpu->fpsr.xmod = ssr.u.fields.xmod;

    memcpy(&scr, &(fpu->fpcr), sizeof(struct swapped_m88k_fpcr));
    scr.u.word = swap32(scr.u.word);
    fpu->fpcr.efinx = scr.u.fields.efinx;
    fpu->fpcr.efovf = scr.u.fields.efovf;
    fpu->fpcr.efunf = scr.u.fields.efunf;
    fpu->fpcr.efdvz = scr.u.fields.efdvz;
    fpu->fpcr.efinv = scr.u.fields.efinv;
    fpu->fpcr.rm = scr.u.fields.rm;
  }
  else
  {
    ssr.u.fields.afinx = fpu->fpsr.afinx;
    ssr.u.fields.afovf = fpu->fpsr.afovf;
    ssr.u.fields.afunf = fpu->fpsr.afunf;
    ssr.u.fields.afdvz = fpu->fpsr.afdvz;
    ssr.u.fields.afinv = fpu->fpsr.afinv;
    ssr.u.fields.xmod = fpu->fpsr.xmod;
    ssr.u.word = swap32(ssr.u.word);
    memcpy(&(fpu->fpsr), &ssr, sizeof(struct swapped_m88k_fpsr));

    scr.u.fields.efinx = fpu->fpcr.efinx;
    scr.u.fields.efovf = fpu->fpcr.efovf;
    scr.u.fields.efunf = fpu->fpcr.efunf;
    scr.u.fields.efdvz = fpu->fpcr.efdvz;
    scr.u.fields.efinv = fpu->fpcr.efinv;
    scr.u.fields.rm = fpu->fpcr.rm;
    scr.u.word = swap32(scr.u.word);
    memcpy(&(fpu->fpcr), &scr, sizeof(struct swapped_m88k_fpcr));
  }
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_user_t(m88k_thread_state_user_t *user)
{
  user->user = swap32(user->user);
}

//--------------------------------------------------------------------------
local void swap_m88110_thread_state_impl_t(m88110_thread_state_impl_t *spu)
{
  uint32 i;

  struct swapped_m88110_bp_ctrl
  {
    union
    {
      struct
      {
        unsigned        v:BIT_WIDTH(0);
        m88110_match_t  addr_match:BITS_WIDTH(12,1);
        unsigned        :BITS_WIDTH(26,13);
        unsigned        rwm:BIT_WIDTH(27);
        unsigned        rw:BIT_WIDTH(28);
        unsigned        :BITS_WIDTH(31,29);
      } fields;
      uint32 word;
    } u;
  } sbpc;

  struct swap_m88110_psr
  {
    union
    {
      struct
      {
        unsigned        :BITS_WIDTH(1,0);
        unsigned mxm_dis:BIT_WIDTH(2);
        unsigned sfu1dis:BIT_WIDTH(3);
        unsigned        :BITS_WIDTH(22,4);
        unsigned trace  :BIT_WIDTH(23);
        unsigned        :BIT_WIDTH(24);
        unsigned sm     :BIT_WIDTH(25);
        unsigned sgn_imd:BIT_WIDTH(26);
        unsigned        :BIT_WIDTH(27);
        unsigned c      :BIT_WIDTH(28);
        unsigned se     :BIT_WIDTH(29);
        unsigned le     :BIT_WIDTH(30);
        unsigned supr   :BIT_WIDTH(31);
      } fields;
      uint32 word;
    } u;
  } spsr;

  struct swapped_m88110_fp_trap_status
  {
    union
    {
      struct
      {
        unsigned        efinx:BIT_WIDTH(0);
        unsigned        efovf:BIT_WIDTH(1);
        unsigned        efunf:BIT_WIDTH(2);
        unsigned        efdvz:BIT_WIDTH(3);
        unsigned        efinv:BIT_WIDTH(4);
        unsigned        priv:BIT_WIDTH(5);
        unsigned        unimp:BIT_WIDTH(6);
        unsigned        int:BIT_WIDTH(7);
        unsigned        sfu1_disabled:BIT_WIDTH(8);
        unsigned        :BITS_WIDTH(13,9);
        m88110_iresult_size_t   iresult_size:BITS_WIDTH(15,14);
        unsigned        :BITS_WIDTH(31,16);
      } fields;
      uint32 word;
    } u;
  } sfps;

  if ( !mf )
  {
    for ( i = 0; i < M88110_N_DATA_BP; i++ )
    {
      spu->data_bp[i].addr = swap32(spu->data_bp[i].addr);
      memcpy(&sbpc, &(spu->data_bp[i].ctrl),
             sizeof(struct swapped_m88110_bp_ctrl));
      sbpc.u.word = swap32(sbpc.u.word);
      spu->data_bp[i].ctrl.v = sbpc.u.fields.v;
      spu->data_bp[i].ctrl.addr_match = sbpc.u.fields.addr_match;
      spu->data_bp[i].ctrl.rwm = sbpc.u.fields.rwm;
      spu->data_bp[i].ctrl.rw = sbpc.u.fields.rw;
    }

    memcpy(&spsr, &(spu->psr), sizeof(struct swap_m88110_psr));
    spsr.u.word = swap32(spsr.u.word);
    spu->psr.mxm_dis = spsr.u.fields.mxm_dis;
    spu->psr.sfu1dis = spsr.u.fields.sfu1dis;
    spu->psr.trace = spsr.u.fields.trace;
    spu->psr.sm = spsr.u.fields.sm;
    spu->psr.sgn_imd = spsr.u.fields.sgn_imd;
    spu->psr.c = spsr.u.fields.c;
    spu->psr.se = spsr.u.fields.se;
    spu->psr.le = spsr.u.fields.le;
    spu->psr.supr = spsr.u.fields.supr;

    memcpy(&sfps, &(spu->fp_trap_status),
           sizeof(struct swapped_m88110_fp_trap_status));
    sfps.u.word = swap32(sfps.u.word);
    spu->fp_trap_status.efinx = sfps.u.fields.efinx;
    spu->fp_trap_status.efovf = sfps.u.fields.efovf;
    spu->fp_trap_status.efunf = sfps.u.fields.efunf;
    spu->fp_trap_status.efdvz = sfps.u.fields.efdvz;
    spu->fp_trap_status.efinv = sfps.u.fields.efinv;
    spu->fp_trap_status.priv = sfps.u.fields.priv;
    spu->fp_trap_status.unimp = sfps.u.fields.unimp;
    spu->fp_trap_status.sfu1_disabled = sfps.u.fields.sfu1_disabled;
    spu->fp_trap_status.iresult_size = sfps.u.fields.iresult_size;
  }
  else
  {
    for ( i = 0; i < M88110_N_DATA_BP; i++ )
    {
      spu->data_bp[i].addr = swap32(spu->data_bp[i].addr);
      sbpc.u.fields.v = spu->data_bp[i].ctrl.v;
      sbpc.u.fields.addr_match = spu->data_bp[i].ctrl.addr_match;
      sbpc.u.fields.rwm = spu->data_bp[i].ctrl.rwm;
      sbpc.u.fields.rw = spu->data_bp[i].ctrl.rw;
      sbpc.u.word = swap32(sbpc.u.word);
      memcpy(&(spu->data_bp[i].ctrl), &sbpc,
             sizeof(struct swapped_m88110_bp_ctrl));
    }

    spsr.u.fields.mxm_dis = spu->psr.mxm_dis;
    spsr.u.fields.sfu1dis = spu->psr.sfu1dis;
    spsr.u.fields.trace = spu->psr.trace;
    spsr.u.fields.sm = spu->psr.sm;
    spsr.u.fields.sgn_imd = spu->psr.sgn_imd;
    spsr.u.fields.c = spu->psr.c;
    spsr.u.fields.se = spu->psr.se;
    spsr.u.fields.le = spu->psr.le;
    spsr.u.fields.supr = spu->psr.supr;
    spsr.u.word = swap32(spsr.u.word);
    memcpy(&(spu->psr), &spsr, sizeof(struct swap_m88110_psr));

    sfps.u.fields.efinx = spu->fp_trap_status.efinx;
    sfps.u.fields.efovf = spu->fp_trap_status.efovf;
    sfps.u.fields.efunf = spu->fp_trap_status.efunf;
    sfps.u.fields.efdvz = spu->fp_trap_status.efdvz;
    sfps.u.fields.efinv = spu->fp_trap_status.efinv;
    sfps.u.fields.priv = spu->fp_trap_status.priv;
    sfps.u.fields.unimp = spu->fp_trap_status.unimp;
    sfps.u.fields.sfu1_disabled = spu->fp_trap_status.sfu1_disabled;
    sfps.u.fields.iresult_size = spu->fp_trap_status.iresult_size;
    sfps.u.word = swap32(sfps.u.word);
    memcpy(&(spu->fp_trap_status), &sfps,
           sizeof(struct swapped_m88110_fp_trap_status));
  }
  spu->intermediate_result.x[0] =
    swap32(spu->intermediate_result.x[0]);
  spu->intermediate_result.x[1] =
    swap32(spu->intermediate_result.x[1]);
  spu->intermediate_result.x[2] =
    swap32(spu->intermediate_result.x[2]);
  spu->intermediate_result.x[3] =
    swap32(spu->intermediate_result.x[3]);
}

//--------------------------------------------------------------------------
local void swap_i860_thread_state_regs(struct i860_thread_state_regs *cpu)
{
  uint32 i;

  for ( i = 0; i < 31; i++ )
    cpu->ireg[i] = swap32(cpu->ireg[i]);
  for ( i = 0; i < 30; i++ )
    cpu->freg[i] = swap32(cpu->freg[i]);
  cpu->psr = swap32(cpu->psr);
  cpu->epsr = swap32(cpu->epsr);
  cpu->db = swap32(cpu->db);
  cpu->pc = swap32(cpu->pc);
  cpu->_padding_ = swap32(cpu->_padding_);
  cpu->Mres3 = SWAP_DOUBLE(cpu->Mres3);
  cpu->Ares3 = SWAP_DOUBLE(cpu->Ares3);
  cpu->Mres2 = SWAP_DOUBLE(cpu->Mres2);
  cpu->Ares2 = SWAP_DOUBLE(cpu->Ares2);
  cpu->Mres1 = SWAP_DOUBLE(cpu->Mres1);
  cpu->Ares1 = SWAP_DOUBLE(cpu->Ares1);
  cpu->Ires1 = SWAP_DOUBLE(cpu->Ires1);
  cpu->Lres3m = SWAP_DOUBLE(cpu->Lres3m);
  cpu->Lres2m = SWAP_DOUBLE(cpu->Lres2m);
  cpu->Lres1m = SWAP_DOUBLE(cpu->Lres1m);
  cpu->KR = SWAP_DOUBLE(cpu->KR);
  cpu->KI = SWAP_DOUBLE(cpu->KI);
  cpu->T = SWAP_DOUBLE(cpu->T);
  cpu->Fsr3 = swap32(cpu->Fsr3);
  cpu->Fsr2 = swap32(cpu->Fsr2);
  cpu->Fsr1 = swap32(cpu->Fsr1);
  cpu->Mergelo32 = swap32(cpu->Mergelo32);
  cpu->Mergehi32 = swap32(cpu->Mergehi32);
}
*/

#if defined(EFD_COMPILE)
//--------------------------------------------------------------------------
local void swap_arm_thread_state(arm_thread_state_t *cpu)
{
  for ( int i = 0; i < 13; i++ )
    cpu->__r[i] = swap32(cpu->__r[i]);
  cpu->__sp = swap32(cpu->__sp);
  cpu->__lr = swap32(cpu->__lr);
  cpu->__pc = swap32(cpu->__pc);
  cpu->__cpsr = swap32(cpu->__cpsr);
}

//--------------------------------------------------------------------------
local void swap_arm_thread_state64(arm_thread_state64_t *cpu)
{
  for ( int i = 0; i < 29; i++ )
    cpu->__x[i] = swap64(cpu->__x[i]);
  cpu->__fp = swap64(cpu->__fp);
  cpu->__lr = swap64(cpu->__lr);
  cpu->__sp = swap64(cpu->__sp);
  cpu->__pc = swap64(cpu->__pc);
  cpu->__cpsr = swap32(cpu->__cpsr);
}

//--------------------------------------------------------------------------
local void swap_i386_thread_state(i386_thread_state_t *cpu)
{
  cpu->__eax = swap32(cpu->__eax);
  cpu->__ebx = swap32(cpu->__ebx);
  cpu->__ecx = swap32(cpu->__ecx);
  cpu->__edx = swap32(cpu->__edx);
  cpu->__edi = swap32(cpu->__edi);
  cpu->__esi = swap32(cpu->__esi);
  cpu->__ebp = swap32(cpu->__ebp);
  cpu->__esp = swap32(cpu->__esp);
  cpu->__ss = swap32(cpu->__ss);
  cpu->__eflags = swap32(cpu->__eflags);
  cpu->__eip = swap32(cpu->__eip);
  cpu->__cs = swap32(cpu->__cs);
  cpu->__ds = swap32(cpu->__ds);
  cpu->__es = swap32(cpu->__es);
  cpu->__fs = swap32(cpu->__fs);
  cpu->__gs = swap32(cpu->__gs);
}

//--------------------------------------------------------------------------
local void swap_x86_thread_state64(x86_thread_state64_t *cpu)
{
  cpu->__rax = swap64(cpu->__rax);
  cpu->__rbx = swap64(cpu->__rbx);
  cpu->__rcx = swap64(cpu->__rcx);
  cpu->__rdx = swap64(cpu->__rdx);
  cpu->__rdi = swap64(cpu->__rdi);
  cpu->__rsi = swap64(cpu->__rsi);
  cpu->__rbp = swap64(cpu->__rbp);
  cpu->__rsp = swap64(cpu->__rsp);
  cpu->__rflags = swap64(cpu->__rflags);
  cpu->__rip = swap64(cpu->__rip);
  cpu->__r8 = swap64(cpu->__r8);
  cpu->__r9 = swap64(cpu->__r9);
  cpu->__r10 = swap64(cpu->__r10);
  cpu->__r11 = swap64(cpu->__r11);
  cpu->__r12 = swap64(cpu->__r12);
  cpu->__r13 = swap64(cpu->__r13);
  cpu->__r14 = swap64(cpu->__r14);
  cpu->__r15 = swap64(cpu->__r15);
  cpu->__cs = swap64(cpu->__cs);
  cpu->__fs = swap64(cpu->__fs);
  cpu->__gs = swap64(cpu->__gs);
}
#endif

//--------------------------------------------------------------------------
#if 0 // !defined(EFD_COMPILE) && !defined(LOADER_COMPILE)
local void swap_x86_state_hdr(x86_state_hdr_t *hdr)
{
  hdr->flavor = swap32(hdr->flavor);
  hdr->count = swap32(hdr->count);
}

//--------------------------------------------------------------------------
local void swap_x86_float_state64(x86_float_state64_t *fpu)
{
  struct swapped_fp_control
  {
    union
    {
      struct
      {
        unsigned short
          :3,
        /*inf*/ :1,
        rc      :2,
        pc      :2,
          :2,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
    } u;
  } sfpc;

  struct swapped_fp_status
  {
    union
    {
      struct
      {
        unsigned short
        busy    :1,
        c3      :1,
        tos     :3,
        c2      :1,
        c1      :1,
        c0      :1,
        errsumm :1,
        stkflt  :1,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
    } u;
  } sfps;

  fpu->__fpu_reserved[0] = swap32(fpu->__fpu_reserved[0]);
  fpu->__fpu_reserved[1] = swap32(fpu->__fpu_reserved[1]);

  if ( !mf )
  {
    memcpy(&sfpc, &(fpu->__fpu_fcw),
      sizeof(struct swapped_fp_control));
    sfpc.u.half = swap16(sfpc.u.half);
    fpu->__fpu_fcw.__rc = sfpc.u.fields.rc;
    fpu->__fpu_fcw.__pc = sfpc.u.fields.pc;
    fpu->__fpu_fcw.__precis = sfpc.u.fields.precis;
    fpu->__fpu_fcw.__undfl = sfpc.u.fields.undfl;
    fpu->__fpu_fcw.__ovrfl = sfpc.u.fields.ovrfl;
    fpu->__fpu_fcw.__zdiv = sfpc.u.fields.zdiv;
    fpu->__fpu_fcw.__denorm = sfpc.u.fields.denorm;
    fpu->__fpu_fcw.__invalid = sfpc.u.fields.invalid;

    memcpy(&sfps, &(fpu->__fpu_fsw),
      sizeof(struct swapped_fp_status));
    sfps.u.half = swap16(sfps.u.half);
    fpu->__fpu_fsw.__busy = sfps.u.fields.busy;
    fpu->__fpu_fsw.__c3 = sfps.u.fields.c3;
    fpu->__fpu_fsw.__tos = sfps.u.fields.tos;
    fpu->__fpu_fsw.__c2 = sfps.u.fields.c2;
    fpu->__fpu_fsw.__c1 = sfps.u.fields.c1;
    fpu->__fpu_fsw.__c0 = sfps.u.fields.c0;
    fpu->__fpu_fsw.__errsumm = sfps.u.fields.errsumm;
    fpu->__fpu_fsw.__stkflt = sfps.u.fields.stkflt;
    fpu->__fpu_fsw.__precis = sfps.u.fields.precis;
    fpu->__fpu_fsw.__undfl = sfps.u.fields.undfl;
    fpu->__fpu_fsw.__ovrfl = sfps.u.fields.ovrfl;
    fpu->__fpu_fsw.__zdiv = sfps.u.fields.zdiv;
    fpu->__fpu_fsw.__denorm = sfps.u.fields.denorm;
    fpu->__fpu_fsw.__invalid = sfps.u.fields.invalid;
  }
  else
  {
    sfpc.u.fields.rc = fpu->__fpu_fcw.__rc;
    sfpc.u.fields.pc = fpu->__fpu_fcw.__pc;
    sfpc.u.fields.precis = fpu->__fpu_fcw.__precis;
    sfpc.u.fields.undfl = fpu->__fpu_fcw.__undfl;
    sfpc.u.fields.ovrfl = fpu->__fpu_fcw.__ovrfl;
    sfpc.u.fields.zdiv = fpu->__fpu_fcw.__zdiv;
    sfpc.u.fields.denorm = fpu->__fpu_fcw.__denorm;
    sfpc.u.fields.invalid = fpu->__fpu_fcw.__invalid;
    sfpc.u.half = swap16(sfpc.u.half);
    memcpy(&(fpu->__fpu_fcw), &sfpc,
      sizeof(struct swapped_fp_control));

    sfps.u.fields.busy = fpu->__fpu_fsw.__busy;
    sfps.u.fields.c3 = fpu->__fpu_fsw.__c3;
    sfps.u.fields.tos = fpu->__fpu_fsw.__tos;
    sfps.u.fields.c2 = fpu->__fpu_fsw.__c2;
    sfps.u.fields.c1 = fpu->__fpu_fsw.__c1;
    sfps.u.fields.c0 = fpu->__fpu_fsw.__c0;
    sfps.u.fields.errsumm = fpu->__fpu_fsw.__errsumm;
    sfps.u.fields.stkflt = fpu->__fpu_fsw.__stkflt;
    sfps.u.fields.precis = fpu->__fpu_fsw.__precis;
    sfps.u.fields.undfl = fpu->__fpu_fsw.__undfl;
    sfps.u.fields.ovrfl = fpu->__fpu_fsw.__ovrfl;
    sfps.u.fields.zdiv = fpu->__fpu_fsw.__zdiv;
    sfps.u.fields.denorm = fpu->__fpu_fsw.__denorm;
    sfps.u.fields.invalid = fpu->__fpu_fsw.__invalid;
    sfps.u.half = swap16(sfps.u.half);
    memcpy(&(fpu->__fpu_fsw), &sfps,
      sizeof(struct swapped_fp_status));
  }
  fpu->__fpu_fop = swap16(fpu->__fpu_fop);
  fpu->__fpu_ip = swap32(fpu->__fpu_ip);
  fpu->__fpu_cs = swap16(fpu->__fpu_cs);
  fpu->__fpu_rsrv2 = swap16(fpu->__fpu_rsrv2);
  fpu->__fpu_dp = swap32(fpu->__fpu_dp);
  fpu->__fpu_ds = swap16(fpu->__fpu_ds);
  fpu->__fpu_rsrv3 = swap16(fpu->__fpu_rsrv3);
  fpu->__fpu_mxcsr = swap32(fpu->__fpu_mxcsr);
  fpu->__fpu_mxcsrmask = swap32(fpu->__fpu_mxcsrmask);
  fpu->__fpu_reserved1 = swap32(fpu->__fpu_reserved1);
}

//--------------------------------------------------------------------------
local void swap_x86_exception_state64(x86_exception_state64_t *exc)
{
  exc->__trapno = swap32(exc->__trapno);
  exc->__err = swap32(exc->__err);
  exc->__faultvaddr = swap64(exc->__faultvaddr);
}

//--------------------------------------------------------------------------
local void swap_x86_debug_state32(x86_debug_state32_t *debug)
{
  debug->__dr0 = swap32(debug->__dr0);
  debug->__dr1 = swap32(debug->__dr1);
  debug->__dr2 = swap32(debug->__dr2);
  debug->__dr3 = swap32(debug->__dr3);
  debug->__dr4 = swap32(debug->__dr4);
  debug->__dr5 = swap32(debug->__dr5);
  debug->__dr6 = swap32(debug->__dr6);
  debug->__dr7 = swap32(debug->__dr7);
}

//--------------------------------------------------------------------------
local void swap_x86_debug_state64(x86_debug_state64_t *debug)
{
  debug->__dr0 = swap64(debug->__dr0);
  debug->__dr1 = swap64(debug->__dr1);
  debug->__dr2 = swap64(debug->__dr2);
  debug->__dr3 = swap64(debug->__dr3);
  debug->__dr4 = swap64(debug->__dr4);
  debug->__dr5 = swap64(debug->__dr5);
  debug->__dr6 = swap64(debug->__dr6);
  debug->__dr7 = swap64(debug->__dr7);
}
#endif  // !EFD_COMPILE && !LOADER_COMPILE

/* current i386 thread states */
#if i386_THREAD_STATE == 1
void swap_i386_float_state(i386_float_state_t *fpu)
{
#ifndef i386_EXCEPTION_STATE_COUNT
  /* this routine does nothing as their are currently no non-byte fields */
#else /* !defined(i386_EXCEPTION_STATE_COUNT) */
  struct swapped_fp_control
  {
    union
    {
      struct
      {
        unsigned short
          :3,
        /*inf*/ :1,
        rc      :2,
        pc      :2,
          :2,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
    } u;
  } sfpc;

  struct swapped_fp_status
  {
    union
    {
      struct
      {
        unsigned short
        busy    :1,
        c3      :1,
        tos     :3,
        c2      :1,
        c1      :1,
        c0      :1,
        errsumm :1,
        stkflt  :1,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
    } u;
  } sfps;

//    enum NXByteOrder host_byte_sex;

  fpu->__fpu_reserved[0] = swap32(fpu->__fpu_reserved[0]);
  fpu->__fpu_reserved[1] = swap32(fpu->__fpu_reserved[1]);

  sfpc.u.fields.rc = fpu->__fpu_fcw.__rc;
  sfpc.u.fields.pc = fpu->__fpu_fcw.__pc;
  sfpc.u.fields.precis = fpu->__fpu_fcw.__precis;
  sfpc.u.fields.undfl = fpu->__fpu_fcw.__undfl;
  sfpc.u.fields.ovrfl = fpu->__fpu_fcw.__ovrfl;
  sfpc.u.fields.zdiv = fpu->__fpu_fcw.__zdiv;
  sfpc.u.fields.denorm = fpu->__fpu_fcw.__denorm;
  sfpc.u.fields.invalid = fpu->__fpu_fcw.__invalid;
  sfpc.u.half = swap16(sfpc.u.half);
  memcpy(&(fpu->__fpu_fcw), &sfpc, sizeof(struct swapped_fp_control));    //-V512 A call of the 'memcpy' function will lead to underflow of the buffer

  sfps.u.fields.busy = fpu->__fpu_fsw.__busy;
  sfps.u.fields.c3 = fpu->__fpu_fsw.__c3;
  sfps.u.fields.tos = fpu->__fpu_fsw.__tos;
  sfps.u.fields.c2 = fpu->__fpu_fsw.__c2;
  sfps.u.fields.c1 = fpu->__fpu_fsw.__c1;
  sfps.u.fields.c0 = fpu->__fpu_fsw.__c0;
  sfps.u.fields.errsumm = fpu->__fpu_fsw.__errsumm;
  sfps.u.fields.stkflt = fpu->__fpu_fsw.__stkflt;
  sfps.u.fields.precis = fpu->__fpu_fsw.__precis;
  sfps.u.fields.undfl = fpu->__fpu_fsw.__undfl;
  sfps.u.fields.ovrfl = fpu->__fpu_fsw.__ovrfl;
  sfps.u.fields.zdiv = fpu->__fpu_fsw.__zdiv;
  sfps.u.fields.denorm = fpu->__fpu_fsw.__denorm;
  sfps.u.fields.invalid = fpu->__fpu_fsw.__invalid;
  sfps.u.half = swap16(sfps.u.half);
  memcpy(&(fpu->__fpu_fsw), &sfps, sizeof(struct swapped_fp_status));

  fpu->__fpu_fop = swap16(fpu->__fpu_fop);
  fpu->__fpu_ip = swap32(fpu->__fpu_ip);
  fpu->__fpu_cs = swap16(fpu->__fpu_cs);
  fpu->__fpu_rsrv2 = swap16(fpu->__fpu_rsrv2);
  fpu->__fpu_dp = swap32(fpu->__fpu_dp);
  fpu->__fpu_ds = swap16(fpu->__fpu_ds);
  fpu->__fpu_rsrv3 = swap16(fpu->__fpu_rsrv3);
  fpu->__fpu_mxcsr = swap32(fpu->__fpu_mxcsr);
  fpu->__fpu_mxcsrmask = swap32(fpu->__fpu_mxcsrmask);
  fpu->__fpu_reserved1 = swap32(fpu->__fpu_reserved1);

#endif /* !defined(i386_EXCEPTION_STATE_COUNT) */
}

void swap_i386_exception_state(i386_exception_state_t *exc)
{
  exc->__trapno = swap32(exc->__trapno);
  exc->__err = swap32(exc->__err);
  exc->__faultvaddr = swap32(exc->__faultvaddr);
}
#endif /* i386_THREAD_STATE == 1 */

//--------------------------------------------------------------------------
/*
local void swap_hppa_integer_thread_state(struct hp_pa_integer_thread_state *regs)
{
  regs->ts_gr1 = swap32(regs->ts_gr1);
  regs->ts_gr2 = swap32(regs->ts_gr2);
  regs->ts_gr3 = swap32(regs->ts_gr3);
  regs->ts_gr4 = swap32(regs->ts_gr4);
  regs->ts_gr5 = swap32(regs->ts_gr5);
  regs->ts_gr6 = swap32(regs->ts_gr6);
  regs->ts_gr7 = swap32(regs->ts_gr7);
  regs->ts_gr8 = swap32(regs->ts_gr8);
  regs->ts_gr9 = swap32(regs->ts_gr9);
  regs->ts_gr10 = swap32(regs->ts_gr10);
  regs->ts_gr11 = swap32(regs->ts_gr11);
  regs->ts_gr12 = swap32(regs->ts_gr12);
  regs->ts_gr13 = swap32(regs->ts_gr13);
  regs->ts_gr14 = swap32(regs->ts_gr14);
  regs->ts_gr15 = swap32(regs->ts_gr15);
  regs->ts_gr16 = swap32(regs->ts_gr16);
  regs->ts_gr17 = swap32(regs->ts_gr17);
  regs->ts_gr18 = swap32(regs->ts_gr18);
  regs->ts_gr19 = swap32(regs->ts_gr19);
  regs->ts_gr20 = swap32(regs->ts_gr20);
  regs->ts_gr21 = swap32(regs->ts_gr21);
  regs->ts_gr22 = swap32(regs->ts_gr22);
  regs->ts_gr23 = swap32(regs->ts_gr23);
  regs->ts_gr24 = swap32(regs->ts_gr24);
  regs->ts_gr25 = swap32(regs->ts_gr25);
  regs->ts_gr26 = swap32(regs->ts_gr26);
  regs->ts_gr27 = swap32(regs->ts_gr27);
  regs->ts_gr28 = swap32(regs->ts_gr28);
  regs->ts_gr29 = swap32(regs->ts_gr29);
  regs->ts_gr30 = swap32(regs->ts_gr30);
  regs->ts_gr31 = swap32(regs->ts_gr31);
  regs->ts_sr0 = swap32(regs->ts_sr0);
  regs->ts_sr1 = swap32(regs->ts_sr1);
  regs->ts_sr2 = swap32(regs->ts_sr2);
  regs->ts_sr3 = swap32(regs->ts_sr3);
  regs->ts_sar = swap32(regs->ts_sar);
}

//--------------------------------------------------------------------------
local void swap_hppa_frame_thread_state( struct hp_pa_frame_thread_state *frame)
{
  frame->ts_pcsq_front = swap32(frame->ts_pcsq_front);
  frame->ts_pcsq_back = swap32(frame->ts_pcsq_back);
  frame->ts_pcoq_front = swap32(frame->ts_pcoq_front);
  frame->ts_pcoq_back = swap32(frame->ts_pcoq_back);
  frame->ts_psw = swap32(frame->ts_psw);
  frame->ts_unaligned_faults = swap32(frame->ts_unaligned_faults);
  frame->ts_fault_address = swap32(frame->ts_fault_address);
  frame->ts_step_range_start = swap32(frame->ts_step_range_start);
  frame->ts_step_range_stop = swap32(frame->ts_step_range_stop);
}

//--------------------------------------------------------------------------
local void swap_hppa_fp_thread_state( struct hp_pa_fp_thread_state *fp)
{
  fp->ts_fp0 = SWAP_DOUBLE(fp->ts_fp0);
  fp->ts_fp1 = SWAP_DOUBLE(fp->ts_fp1);
  fp->ts_fp2 = SWAP_DOUBLE(fp->ts_fp2);
  fp->ts_fp3 = SWAP_DOUBLE(fp->ts_fp3);
  fp->ts_fp4 = SWAP_DOUBLE(fp->ts_fp4);
  fp->ts_fp5 = SWAP_DOUBLE(fp->ts_fp5);
  fp->ts_fp6 = SWAP_DOUBLE(fp->ts_fp6);
  fp->ts_fp7 = SWAP_DOUBLE(fp->ts_fp7);
  fp->ts_fp8 = SWAP_DOUBLE(fp->ts_fp8);
  fp->ts_fp9 = SWAP_DOUBLE(fp->ts_fp9);
  fp->ts_fp10 = SWAP_DOUBLE(fp->ts_fp10);
  fp->ts_fp11 = SWAP_DOUBLE(fp->ts_fp11);
  fp->ts_fp12 = SWAP_DOUBLE(fp->ts_fp12);
  fp->ts_fp13 = SWAP_DOUBLE(fp->ts_fp13);
  fp->ts_fp14 = SWAP_DOUBLE(fp->ts_fp14);
  fp->ts_fp15 = SWAP_DOUBLE(fp->ts_fp15);
  fp->ts_fp16 = SWAP_DOUBLE(fp->ts_fp16);
  fp->ts_fp17 = SWAP_DOUBLE(fp->ts_fp17);
  fp->ts_fp18 = SWAP_DOUBLE(fp->ts_fp18);
  fp->ts_fp19 = SWAP_DOUBLE(fp->ts_fp19);
  fp->ts_fp20 = SWAP_DOUBLE(fp->ts_fp20);
  fp->ts_fp21 = SWAP_DOUBLE(fp->ts_fp21);
  fp->ts_fp22 = SWAP_DOUBLE(fp->ts_fp22);
  fp->ts_fp23 = SWAP_DOUBLE(fp->ts_fp23);
  fp->ts_fp24 = SWAP_DOUBLE(fp->ts_fp24);
  fp->ts_fp25 = SWAP_DOUBLE(fp->ts_fp25);
  fp->ts_fp26 = SWAP_DOUBLE(fp->ts_fp26);
  fp->ts_fp27 = SWAP_DOUBLE(fp->ts_fp27);
  fp->ts_fp28 = SWAP_DOUBLE(fp->ts_fp28);
  fp->ts_fp29 = SWAP_DOUBLE(fp->ts_fp29);
  fp->ts_fp30 = SWAP_DOUBLE(fp->ts_fp30);
  fp->ts_fp31 = SWAP_DOUBLE(fp->ts_fp31);
}

//--------------------------------------------------------------------------
local void swap_sparc_thread_state_regs(struct sparc_thread_state_regs *cpu)
{
  struct swapped_psr
  {
    union
    {
      struct
      {
        unsigned int
        cwp:BITS_WIDTH(4,0),
        et:BIT_WIDTH(5),
        ps:BIT_WIDTH(6),
        s:BIT_WIDTH(7),
        pil:BITS_WIDTH(11,8),
        ef:BIT_WIDTH(12),
        ec:BIT_WIDTH(13),
        reserved:BITS_WIDTH(19,14),
        icc:BITS_WIDTH(23,20),
        ver:BITS_WIDTH(27,24),
        impl:BITS_WIDTH(31,28);
      } fields;
      unsigned int word;
    } u;
  } spsr;
  struct p_status *pr_status;

  cpu->regs.r_pc = swap32(cpu->regs.r_pc);
  cpu->regs.r_npc = swap32(cpu->regs.r_npc);
  cpu->regs.r_y = swap32(cpu->regs.r_y);
  cpu->regs.r_g1 = swap32(cpu->regs.r_g1);
  cpu->regs.r_g2 = swap32(cpu->regs.r_g2);
  cpu->regs.r_g3 = swap32(cpu->regs.r_g3);
  cpu->regs.r_g4 = swap32(cpu->regs.r_g4);
  cpu->regs.r_g5 = swap32(cpu->regs.r_g5);
  cpu->regs.r_g6 = swap32(cpu->regs.r_g6);
  cpu->regs.r_g7 = swap32(cpu->regs.r_g7);
  cpu->regs.r_o0 = swap32(cpu->regs.r_o0);
  cpu->regs.r_o1 = swap32(cpu->regs.r_o1);
  cpu->regs.r_o2 = swap32(cpu->regs.r_o2);
  cpu->regs.r_o3 = swap32(cpu->regs.r_o3);
  cpu->regs.r_o4 = swap32(cpu->regs.r_o4);
  cpu->regs.r_o5 = swap32(cpu->regs.r_o5);
  cpu->regs.r_o6 = swap32(cpu->regs.r_o6);
  cpu->regs.r_o7 = swap32(cpu->regs.r_o7);

  pr_status = (struct p_status *) &(cpu->regs.r_psr);
  if ( !mf )
  {
    memcpy(&spsr, &(cpu->regs.r_psr), sizeof(struct swapped_psr));
    spsr.u.word = swap32(spsr.u.word);
    pr_status->PSRREG.psr_bits.cwp = spsr.u.fields.cwp;
    pr_status->PSRREG.psr_bits.ps = spsr.u.fields.ps;
    pr_status->PSRREG.psr_bits.s = spsr.u.fields.s;
    pr_status->PSRREG.psr_bits.pil = spsr.u.fields.pil;
    pr_status->PSRREG.psr_bits.ef = spsr.u.fields.ef;
    pr_status->PSRREG.psr_bits.ec = spsr.u.fields.ec;
    pr_status->PSRREG.psr_bits.reserved = spsr.u.fields.reserved;
    pr_status->PSRREG.psr_bits.icc = spsr.u.fields.icc;
    pr_status->PSRREG.psr_bits.et = spsr.u.fields.ver;
    pr_status->PSRREG.psr_bits.impl = spsr.u.fields.impl;
  }
  else
  {
    spsr.u.fields.cwp = pr_status->PSRREG.psr_bits.cwp;
    spsr.u.fields.ps = pr_status->PSRREG.psr_bits.ps;
    spsr.u.fields.s = pr_status->PSRREG.psr_bits.s;
    spsr.u.fields.pil = pr_status->PSRREG.psr_bits.pil;
    spsr.u.fields.ef = pr_status->PSRREG.psr_bits.ef;
    spsr.u.fields.ec = pr_status->PSRREG.psr_bits.ec;
    spsr.u.fields.reserved = pr_status->PSRREG.psr_bits.reserved;
    spsr.u.fields.icc = pr_status->PSRREG.psr_bits.icc;
    spsr.u.fields.ver = pr_status->PSRREG.psr_bits.et;
    spsr.u.fields.impl = pr_status->PSRREG.psr_bits.impl;
    spsr.u.word = swap32(spsr.u.word);
    memcpy(&(cpu->regs.r_psr), &spsr, sizeof(struct swapped_psr));
  }
}

//--------------------------------------------------------------------------
local void swap_sparc_thread_state_fpu(struct sparc_thread_state_fpu *fpu)
{
  struct swapped_fsr
  {
    union
    {
      struct
      {
        unsigned int
        cexc:BITS_WIDTH(4,0),
        aexc:BITS_WIDTH(9,5),
        fcc:BITS_WIDTH(11,10),
        pr:BIT_WIDTH(12),
        qne:BIT_WIDTH(13),
        ftt:BITS_WIDTH(16,14),
        res:BITS_WIDTH(22,17),
        tem:BITS_WIDTH(27,23),
        rp:BITS_WIDTH(29,28),
        rd:BITS_WIDTH(31,30);
      } fields;
      unsigned int word;
    } u;
  } sfsr;
  uint32 i;
  struct f_status *fpu_status;

  // floating point registers
  for ( i = 0; i < 16; i++ )         // 16 doubles
    fpu->fpu.fpu_fr.Fpu_dregs[i] = SWAP_DOUBLE(fpu->fpu.fpu_fr.Fpu_dregs[i]);

  fpu->fpu.Fpu_q[0].FQu.whole = SWAP_DOUBLE(fpu->fpu.Fpu_q[0].FQu.whole);
  fpu->fpu.Fpu_q[1].FQu.whole = SWAP_DOUBLE(fpu->fpu.Fpu_q[1].FQu.whole);
  fpu->fpu.Fpu_flags = swap32(fpu->fpu.Fpu_flags);
  fpu->fpu.Fpu_extra = swap32(fpu->fpu.Fpu_extra);
  fpu->fpu.Fpu_qcnt = swap32(fpu->fpu.Fpu_qcnt);

  fpu_status = (struct f_status *) &(fpu->fpu.Fpu_fsr);
  if ( !mf )
  {
    memcpy(&sfsr, &(fpu->fpu.Fpu_fsr), sizeof(unsigned int));
    sfsr.u.word = swap32(sfsr.u.word);
    fpu_status->FPUREG.Fpu_fsr_bits.rd = sfsr.u.fields.rd;
    fpu_status->FPUREG.Fpu_fsr_bits.rp = sfsr.u.fields.rp;
    fpu_status->FPUREG.Fpu_fsr_bits.tem = sfsr.u.fields.tem;
    fpu_status->FPUREG.Fpu_fsr_bits.res = sfsr.u.fields.res;
    fpu_status->FPUREG.Fpu_fsr_bits.ftt = sfsr.u.fields.ftt;
    fpu_status->FPUREG.Fpu_fsr_bits.qne = sfsr.u.fields.qne;
    fpu_status->FPUREG.Fpu_fsr_bits.pr = sfsr.u.fields.pr;
    fpu_status->FPUREG.Fpu_fsr_bits.fcc = sfsr.u.fields.fcc;
    fpu_status->FPUREG.Fpu_fsr_bits.aexc = sfsr.u.fields.aexc;
    fpu_status->FPUREG.Fpu_fsr_bits.cexc = sfsr.u.fields.cexc;
  }
  else
  {
    sfsr.u.fields.rd = fpu_status->FPUREG.Fpu_fsr_bits.rd;
    sfsr.u.fields.rp = fpu_status->FPUREG.Fpu_fsr_bits.rp;
    sfsr.u.fields.tem = fpu_status->FPUREG.Fpu_fsr_bits.tem;
    sfsr.u.fields.res = fpu_status->FPUREG.Fpu_fsr_bits.res;
    sfsr.u.fields.ftt = fpu_status->FPUREG.Fpu_fsr_bits.ftt;
    sfsr.u.fields.qne = fpu_status->FPUREG.Fpu_fsr_bits.qne;
    sfsr.u.fields.pr = fpu_status->FPUREG.Fpu_fsr_bits.pr;
    sfsr.u.fields.fcc = fpu_status->FPUREG.Fpu_fsr_bits.fcc;
    sfsr.u.fields.aexc = fpu_status->FPUREG.Fpu_fsr_bits.aexc;
    sfsr.u.fields.cexc = fpu_status->FPUREG.Fpu_fsr_bits.cexc;
    sfsr.u.word = swap32(sfsr.u.word);
    memcpy(&(fpu->fpu.Fpu_fsr), &sfsr, sizeof(struct swapped_fsr));
  }
}
*/
//--------------------------------------------------------------------------
local void swap_ident_command(struct ident_command *id_cmd)
{
  id_cmd->cmd = swap32(id_cmd->cmd);
  id_cmd->cmdsize = swap32(id_cmd->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_routines_command(struct routines_command *r_cmd)
{
  r_cmd->cmd = swap32(r_cmd->cmd);
  r_cmd->cmdsize = swap32(r_cmd->cmdsize);
  r_cmd->init_address = swap32(r_cmd->init_address);
  r_cmd->init_module = swap32(r_cmd->init_module);
  r_cmd->reserved1 = swap32(r_cmd->reserved1);
  r_cmd->reserved2 = swap32(r_cmd->reserved2);
  r_cmd->reserved3 = swap32(r_cmd->reserved3);
  r_cmd->reserved4 = swap32(r_cmd->reserved4);
  r_cmd->reserved5 = swap32(r_cmd->reserved5);
  r_cmd->reserved6 = swap32(r_cmd->reserved6);
}

//--------------------------------------------------------------------------
local void swap_routines_command_64(struct routines_command_64 *r_cmd)
{
  r_cmd->cmd = swap32(r_cmd->cmd);
  r_cmd->cmdsize = swap32(r_cmd->cmdsize);
  r_cmd->init_address = swap64(r_cmd->init_address);
  r_cmd->init_module = swap64(r_cmd->init_module);
  r_cmd->reserved1 = swap64(r_cmd->reserved1);
  r_cmd->reserved2 = swap64(r_cmd->reserved2);
  r_cmd->reserved3 = swap64(r_cmd->reserved3);
  r_cmd->reserved4 = swap64(r_cmd->reserved4);
  r_cmd->reserved5 = swap64(r_cmd->reserved5);
  r_cmd->reserved6 = swap64(r_cmd->reserved6);
}
//--------------------------------------------------------------------------
local void swap_twolevel_hints_command(twolevel_hints_command *hints_cmd)
{
  hints_cmd->cmd = swap32(hints_cmd->cmd);
  hints_cmd->cmdsize = swap32(hints_cmd->cmdsize);
  hints_cmd->offset = swap32(hints_cmd->offset);
  hints_cmd->nhints = swap32(hints_cmd->nhints);
}

//--------------------------------------------------------------------------
local void swap_prebind_cksum_command(prebind_cksum_command *cksum_cmd)
{
  cksum_cmd->cmd = swap32(cksum_cmd->cmd);
  cksum_cmd->cmdsize = swap32(cksum_cmd->cmdsize);
  cksum_cmd->cksum = swap32(cksum_cmd->cksum);
}


//----------------------------------------------------------------------
static void swap_uuid_command(struct uuid_command *uuid_cmd)
{
  uuid_cmd->cmd = swap32(uuid_cmd->cmd);
  uuid_cmd->cmdsize = swap32(uuid_cmd->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_linkedit_data_command(struct linkedit_data_command *ld)
{
  ld->cmd = swap32(ld->cmd);
  ld->cmdsize = swap32(ld->cmdsize);
  ld->dataoff = swap32(ld->dataoff);
  ld->datasize = swap32(ld->datasize);
}

//--------------------------------------------------------------------------
local void swap_entry_point_command(struct entry_point_command *ep)
{
  ep->cmd = swap32(ep->cmd);
  ep->cmdsize = swap32(ep->cmdsize);
  ep->entryoff = swap64(ep->entryoff);
  ep->stacksize = swap64(ep->stacksize);
}

//--------------------------------------------------------------------------
local void swap_source_version_command(struct source_version_command *sv)
{
  sv->cmd = swap32(sv->cmd);
  sv->cmdsize = swap32(sv->cmdsize);
  sv->version = swap64(sv->version);
}

//--------------------------------------------------------------------------
local void swap_rpath_command(struct rpath_command *rpath_cmd)
{
  rpath_cmd->cmd = swap32(rpath_cmd->cmd);
  rpath_cmd->cmdsize = swap32(rpath_cmd->cmdsize);
  rpath_cmd->path.offset = swap32(rpath_cmd->path.offset);
}

//--------------------------------------------------------------------------
local void swap_encryption_info_command(struct encryption_info_command *ec)
{
  ec->cmd = swap32(ec->cmd);
  ec->cmdsize = swap32(ec->cmdsize);
  ec->cryptoff = swap32(ec->cryptoff);
  ec->cryptsize = swap32(ec->cryptsize);
  ec->cryptid = swap32(ec->cryptid);
}

//--------------------------------------------------------------------------
local void swap_encryption_info_command_64(struct encryption_info_command_64 *ec)
{
  ec->cmd = swap32(ec->cmd);
  ec->cmdsize = swap32(ec->cmdsize);
  ec->cryptoff = swap32(ec->cryptoff);
  ec->cryptsize = swap32(ec->cryptsize);
  ec->cryptid = swap32(ec->cryptid);
  ec->pad = swap32(ec->pad);
}
//--------------------------------------------------------------------------
local void swap_dyld_info_command(struct dyld_info_command *ed)
{
  ed->cmd = swap32(ed->cmd);
  ed->cmdsize = swap32(ed->cmdsize);
  ed->rebase_off = swap32(ed->rebase_off);
  ed->rebase_size = swap32(ed->rebase_size);
  ed->bind_off = swap32(ed->bind_off);
  ed->bind_size = swap32(ed->bind_size);
  ed->weak_bind_off = swap32(ed->weak_bind_off);
  ed->weak_bind_size = swap32(ed->weak_bind_size);
  ed->lazy_bind_off = swap32(ed->lazy_bind_off);
  ed->lazy_bind_size = swap32(ed->lazy_bind_size);
  ed->export_off = swap32(ed->export_off);
  ed->export_size = swap32(ed->export_size);
}

//--------------------------------------------------------------------------
local void swap_version_min_command(struct version_min_command *ec)
{
  ec->cmd = swap32(ec->cmd);
  ec->cmdsize = swap32(ec->cmdsize);
  ec->version = swap32(ec->version);
  ec->sdk     = swap32(ec->sdk);
}

//--------------------------------------------------------------------------
local void swap_nlist_64(struct nlist_64 *symbols_from, struct nlist_64 *symbols_to, uint32 nsymbols)
{
  uint32 i;
  for ( i = 0; i < nsymbols; i++ )
  {
    symbols_to[i].n_un.n_strx = swap32(symbols_from[i].n_un.n_strx);
    if ( symbols_to != symbols_from )
    {
      symbols_to[i].n_type = symbols_from[i].n_type;
      symbols_to[i].n_sect = symbols_from[i].n_sect;
    }
    symbols_to[i].n_desc = swap16(symbols_from[i].n_desc);
    symbols_to[i].n_value = swap64(symbols_from[i].n_value);
  }
}

//--------------------------------------------------------------------------
local void nlist_to64(
        const struct nlist *symbols_from,
        struct nlist_64 *symbols_to,
        size_t nsymbols,
        bool swap)
{
  if ( swap )
  {
    for ( size_t i = 0; i < nsymbols; i++ )
    {
      symbols_to[i].n_un.n_strx = swap32(symbols_from[i].n_un.n_strx);
      symbols_to[i].n_type      = symbols_from[i].n_type;
      symbols_to[i].n_sect      = symbols_from[i].n_sect;
      symbols_to[i].n_desc      = swap16(symbols_from[i].n_desc);
      symbols_to[i].n_value     = swap32(symbols_from[i].n_value);
    }
  }
  else
  {
    for ( size_t i = 0; i < nsymbols; i++ )
    {
      symbols_to[i].n_un.n_strx = symbols_from[i].n_un.n_strx;
      symbols_to[i].n_type      = symbols_from[i].n_type;
      symbols_to[i].n_sect      = symbols_from[i].n_sect;
      symbols_to[i].n_desc      = symbols_from[i].n_desc;
      symbols_to[i].n_value     = symbols_from[i].n_value;
    }
  }
}

//--------------------------------------------------------------------------
local void swap_dylib_module_64(struct dylib_module_64 *mods, uint32 nmods)
{
  uint32 i;
  for ( i = 0; i < nmods; i++ )
  {
    mods[i].module_name = swap32(mods[i].module_name);
    mods[i].iextdefsym  = swap32(mods[i].iextdefsym);
    mods[i].nextdefsym  = swap32(mods[i].nextdefsym);
    mods[i].irefsym     = swap32(mods[i].irefsym);
    mods[i].nrefsym     = swap32(mods[i].nrefsym);
    mods[i].ilocalsym   = swap32(mods[i].ilocalsym);
    mods[i].nlocalsym   = swap32(mods[i].nlocalsym);
    mods[i].iextrel     = swap32(mods[i].iextrel);
    mods[i].nextrel     = swap32(mods[i].nextrel);
    mods[i].iinit_iterm = swap32(mods[i].iinit_iterm);
    mods[i].ninit_nterm = swap32(mods[i].ninit_nterm);
    mods[i].objc_module_info_size =
                          swap32(mods[i].objc_module_info_size);
    mods[i].objc_module_info_addr =
                          swap64(mods[i].objc_module_info_addr);
  }
}

//--------------------------------------------------------------------------
local void dylib_module_to64(
        const struct dylib_module *mods_from,
        struct dylib_module_64 *mods_to,
        size_t nmods,
        bool swap)
{
  if ( swap )
  {
    for ( size_t i = 0; i < nmods; i++ )
    {
      mods_to[i].module_name = swap32(mods_from[i].module_name);
      mods_to[i].iextdefsym  = swap32(mods_from[i].iextdefsym);
      mods_to[i].nextdefsym  = swap32(mods_from[i].nextdefsym);
      mods_to[i].irefsym     = swap32(mods_from[i].irefsym);
      mods_to[i].nrefsym     = swap32(mods_from[i].nrefsym);
      mods_to[i].ilocalsym   = swap32(mods_from[i].ilocalsym);
      mods_to[i].nlocalsym   = swap32(mods_from[i].nlocalsym);
      mods_to[i].iextrel     = swap32(mods_from[i].iextrel);
      mods_to[i].nextrel     = swap32(mods_from[i].nextrel);
      mods_to[i].iinit_iterm = swap32(mods_from[i].iinit_iterm);
      mods_to[i].ninit_nterm = swap32(mods_from[i].ninit_nterm);
      mods_to[i].objc_module_info_size =
                            swap32(mods_from[i].objc_module_info_size);
      mods_to[i].objc_module_info_addr =
                            swap32(mods_from[i].objc_module_info_addr);
    }
  }
  else
  {
    for ( size_t i = 0; i < nmods; i++ )
    {
      mods_to[i].module_name = mods_from[i].module_name;
      mods_to[i].iextdefsym  = mods_from[i].iextdefsym;
      mods_to[i].nextdefsym  = mods_from[i].nextdefsym;
      mods_to[i].irefsym     = mods_from[i].irefsym;
      mods_to[i].nrefsym     = mods_from[i].nrefsym;
      mods_to[i].ilocalsym   = mods_from[i].ilocalsym;
      mods_to[i].nlocalsym   = mods_from[i].nlocalsym;
      mods_to[i].iextrel     = mods_from[i].iextrel;
      mods_to[i].nextrel     = mods_from[i].nextrel;
      mods_to[i].iinit_iterm = mods_from[i].iinit_iterm;
      mods_to[i].ninit_nterm = mods_from[i].ninit_nterm;
      mods_to[i].objc_module_info_size =
                            mods_from[i].objc_module_info_size;
      mods_to[i].objc_module_info_addr =
                            mods_from[i].objc_module_info_addr;
    }
  }
}

//--------------------------------------------------------------------------
local void swap_dylib_table_of_contents(struct dylib_table_of_contents *tocs, uint32 ntocs)
{
  for ( uint32 i = 0; i < ntocs; i++ )
  {
    tocs[i].symbol_index = swap32(tocs[i].symbol_index);
    tocs[i].module_index = swap32(tocs[i].module_index);
  }
}

//--------------------------------------------------------------------------
local void swap_dylib_reference(struct dylib_reference *refs, uint32 nrefs)
{
  struct swapped_dylib_reference
  {
    union
    {
      struct
      {
        uint32
            flags:8,
            isym:24;
      } fields;
      uint32 word;
    } u;
  } sref;


  for ( uint32 i = 0; i < nrefs; i++ )
  {
    sref.u.fields.isym = refs[i].isym;
    sref.u.fields.flags = refs[i].flags;
    sref.u.word = swap32(sref.u.word);
    memcpy(refs + i, &sref, sizeof(struct swapped_dylib_reference));
  }
}

//--------------------------------------------------------------------------
local void swap_indirect_symbols(uint32 *indirect_symbols, uint32 nindirect_symbols)
{
  for ( uint32 i = 0; i < nindirect_symbols; i++ )
    indirect_symbols[i] = swap32(indirect_symbols[i]);
}

//--------------------------------------------------------------------------
local void swap_relocation_info(struct relocation_info *relocs, uint32 nrelocs)
{
  uint32 i;
  bool scattered;

  struct swapped_relocation_info
  {
    int32 r_address;
    union
    {
      struct
      {
        unsigned int
            r_type:4,
            r_extern:1,
            r_length:2,
            r_pcrel:1,
            r_symbolnum:24;
      } fields;
      uint32 word;
    } u;
  } sr;
  CASSERT(sizeof(swapped_relocation_info) == sizeof(relocation_info));

  struct swapped_scattered_relocation_info
  {
    uint32 word;
    int32 r_value;
  } *ssr;

  for ( i = 0; i < nrelocs; i++ )
  {
    scattered = (bool)((swap32(relocs[i].r_address) & R_SCATTERED) != 0);
    if ( scattered == FALSE )
    {
      memcpy(&sr, relocs + i, sizeof(struct swapped_relocation_info));
      sr.r_address = swap32(sr.r_address);
      sr.u.word = swap32(sr.u.word);
      relocs[i].r_address = sr.r_address;
      relocs[i].r_symbolnum = sr.u.fields.r_symbolnum;
      relocs[i].r_pcrel = sr.u.fields.r_pcrel;
      relocs[i].r_length = sr.u.fields.r_length;
      relocs[i].r_extern = sr.u.fields.r_extern;
      relocs[i].r_type = sr.u.fields.r_type;
    }
    else
    {
      ssr = (struct swapped_scattered_relocation_info *)(relocs + i);
      ssr->word = swap32(ssr->word);
      ssr->r_value = swap32(ssr->r_value);
    }
  }
}

struct segment_command_64 segment_to64(const struct segment_command &sg)
{
  struct segment_command_64 res;
  res.cmd = sg.cmd;
  res.cmdsize = sg.cmdsize;
  memcpy(res.segname, sg.segname, 16);
  res.vmaddr = sg.vmaddr;
  res.vmsize = sg.vmsize;
  res.fileoff = sg.fileoff;
  res.filesize = sg.filesize;
  res.maxprot = sg.maxprot;
  res.initprot = sg.initprot;
  res.nsects = sg.nsects;
  res.flags = sg.flags;
  return res;
}

struct section_64 section_to64(const struct section &sec)
{
  struct section_64 res;
  memcpy(res.sectname, sec.sectname, 16);
  memcpy(res.segname, sec.segname, 16);
  res.addr = sec.addr;
  res.size = sec.size;
  res.offset = sec.offset;
  res.align = sec.align;
  res.reloff = sec.reloff;
  res.nreloc = sec.nreloc;
  res.flags = sec.flags;
  res.reserved1 = sec.reserved1;
  res.reserved2 = sec.reserved2;
  res.reserved3 = 0;
  return res;
}

#include "base.cpp"

#ifdef LOADER_COMPILE
//--------------------------------------------------------------------------
static const char *convert_cpu(cpu_type_t cputype, cpu_subtype_t cpusubtype, int *p_target, bool mf)
{
  const char *name = NULL;
  switch ( cputype )
  {
    default:
    case CPU_TYPE_VAX:
    case CPU_TYPE_ROMP:
    case CPU_TYPE_NS32032:
    case CPU_TYPE_NS32332:
    case CPU_TYPE_MC88000:
      break;
    case CPU_TYPE_MC680x0:
      name = "68K";
      switch ( cpusubtype )
      {
        case CPU_SUBTYPE_MC680x0_ALL:
          break;
        case CPU_SUBTYPE_MC68030_ONLY:
          name = "68030";
          break;
        case CPU_SUBTYPE_MC68040:
          name = "68040";
          break;
      }
      break;
    case CPU_TYPE_I860:
      name = "860xp";
      switch ( cpusubtype )
      {
        case CPU_SUBTYPE_I860_ALL:
          break;
        case CPU_SUBTYPE_I860_860:
          name = "860xr";
          break;
      }
      break;
    case CPU_TYPE_I386:
      name = "metapc";
      switch ( cpusubtype )
      {
        case CPU_SUBTYPE_I386_ALL:
          break;
        case CPU_SUBTYPE_486:
        case CPU_SUBTYPE_486SX:
          name = "80486p";
          break;
        case CPU_SUBTYPE_PENT: /* same as 586 */
        case CPU_SUBTYPE_PENTPRO:
        case CPU_SUBTYPE_PENTII_M3:
        case CPU_SUBTYPE_PENTII_M5:
          break;
      }
      break;
    case CPU_TYPE_POWERPC:
      name = "ppc";
      break;
    case CPU_TYPE_HPPA:
      name = "hppa";
      break;
    case CPU_TYPE_SPARC:
      name = mf ? "sparcb" : "sparcl";
      break;
    case CPU_TYPE_MIPS:
      name = mf ? "mipsb" : "mipsl";
      break;
    case CPU_TYPE_ARM:
      name = mf ? "armb" : "arm";
      break;
#ifdef __EA64__ // see also below, the error message for it
    case CPU_TYPE_X86_64:
      name = "metapc";
      break;
    case CPU_TYPE_ARM64:
      name = "arm";
      break;
#endif
    case CPU_TYPE_POWERPC64:
      name = "ppc";
      break;
  }
  if ( p_target != NULL )
    *p_target = macho_arch_to_ida_arch(cputype, cpusubtype, NULL);
  return name;
}

//--------------------------------------------------------------------------
static size_t get_cpu_name(cpu_type_t cputype, cpu_subtype_t subtype, char *buf, size_t bufsize)
{
  const char *name;
  const char *subname = "";
  char subbuf[32];
  if ( subtype != 0 )
  {
    qsnprintf(subbuf, sizeof(subbuf), " (subtype 0x%02X)", subtype);
    subname = subbuf;
  }
  switch ( cputype & ~CPU_ARCH_ABI64 )
  {
    case CPU_TYPE_VAX:     name = "VAX";     break;
    case CPU_TYPE_ROMP:    name = "ROMP";    break;
    case CPU_TYPE_NS32032: name = "NS32032"; break;
    case CPU_TYPE_NS32332: name = "NS32332"; break;
    case CPU_TYPE_VEO:     name = "VEO";     break;
    case CPU_TYPE_MC680x0: name = "MC680x0"; break;
    case CPU_TYPE_MC88000: name = "MC88000"; break;
    case CPU_TYPE_I860:    name = "I860";    break;
    case CPU_TYPE_POWERPC: name = "POWERPC"; break;
    case CPU_TYPE_HPPA:    name = "HPPA";    break;
    case CPU_TYPE_SPARC:   name = "SPARC";   break;
    case CPU_TYPE_I386:    name = "I386";
      if ( subtype == CPU_SUBTYPE_I386_ALL ) // same as CPU_SUBTYPE_386
        subname = "";
      break;
    case CPU_TYPE_ARM:
      name = "ARM";
      switch ( subtype )
      {
        case CPU_SUBTYPE_ARM_A500_ARCH:
        case CPU_SUBTYPE_ARM_A500:
          subname = "500";
          break;
        case CPU_SUBTYPE_ARM_A440:
          subname = "440";
          break;
        case CPU_SUBTYPE_ARM_M4:
          subname = " M4";
          break;
        case CPU_SUBTYPE_ARM_V4T:
          subname = "v4T";
          break;
        case CPU_SUBTYPE_ARM_V6:
          subname = "v6";
          break;
        case CPU_SUBTYPE_ARM_V5TEJ:
          subname = "v5TEJ";
          break;
        case CPU_SUBTYPE_ARM_XSCALE:
          subname = " XScale";
          break;
        case CPU_SUBTYPE_ARM_V7:
          subname = "v7";
          break;
        case CPU_SUBTYPE_ARM_V7F:
          subname = "v7F";
          break;
        case CPU_SUBTYPE_ARM_V7K:
          subname = "v7K";
          break;
        case CPU_SUBTYPE_ARM_V7S:
          subname = "v7S";
          break;
        case CPU_SUBTYPE_ARM_V8:
          subname = "v8";
          break;
      }
      break;
    default:
      return qsnprintf(buf, bufsize, "0x%02X%s", cputype, subname);
  }
  if ( cputype & CPU_ARCH_ABI64 )
  {
    switch ( cputype )
    {
      case CPU_TYPE_X86_64:
        name = "X86_64";
        switch ( subtype & ~CPU_SUBTYPE_MASK )
        {
          case CPU_SUBTYPE_X86_ALL:
            subname = "";
            break;
          case CPU_SUBTYPE_X86_ARCH1:
            subname = " (arch1)";
            break;
          case CPU_SUBTYPE_X86_64_H:
            subname = " (x86_64h)";
            break;
        }
        break;
      case CPU_TYPE_POWERPC64:
        name = "POWERPC64"; break;
      case CPU_TYPE_ARM64:
        name = "ARM64";
        switch ( subtype & ~CPU_SUBTYPE_MASK )
        {
          case CPU_SUBTYPE_ARM64_V8:
            subname = "v8"; break;
        }
        break;
      default:
        return qsnprintf(buf, bufsize, "%s64%s", name, subname);
    }
  }
  return qsnprintf(buf, bufsize, "%s%s", name, subname);
}
#endif

// ---------------------------------------------------------------------------
bool macho_file_t::seek_to_subfile(uint n, size_t filesize)
{
  int64 fsize = filesize == 0 ? qlsize(li) : filesize;
  if ( fsize <= 0 )
    return false;

  if ( n == 0 && fat_archs.size() == 0 )
  {
    mach_offset = 0;
    mach_size   = size_t(fsize);
  }
  else if ( n < fat_archs.size() )
  {
    mach_offset = fat_archs[n].offset;
    mach_size   = fat_archs[n].size;
    if ( mach_offset >= size_t(fsize) )
    {
      msg("Fat subfile %i is outside the file\n", n);
      return false;
    }
    if ( mach_offset + mach_size > size_t(fsize) )
    {
      msg("Fat subfile %i is truncated\n", n);
      mach_size = qlsize(li) - mach_offset;
    }
  }
  else
  {
    return false;
  }

  qoff64_t pos = mach_offset + start_offset;
  return qlseek(li, pos) == pos;
}

//--------------------------------------------------------------------------
bool macho_file_t::set_subfile(uint n, size_t filesize, bool silent)
{
  // clear various cached tables
  mach_header_data.clear();
  load_commands.clear();
  mach_segcmds.clear();
  mach_sections.clear();
  mach_dylibs.clear();
  mach_modtable.clear();
  mach_toc.clear();
  mach_reftable.clear();
  parsed_section_info = false;
  base_addr = BADADDR64;

  size_t mh_len;
  subfile_type_t type = get_subfile_type(n, filesize);
  switch ( type )
  {
    default:
      INTERR(20026);

    case SUBFILE_UNKNOWN:
      return false;

    case SUBFILE_AR:
      return select_ar_module(mach_offset, mach_size);

    case SUBFILE_MACH:          // 32-bit file
      m64 = false;
      mh_len = sizeof(mach_header);
      break;

    case SUBFILE_MACH_64:       // 64-bit file
      m64 = true;
      mh_len = sizeof(mach_header_64);
      break;
  }

  mach_header_data.resize(mh_len);
  if ( qlread(li, mach_header_data.begin(), mh_len) != mh_len )
    return false;

  memcpy(&mh, mach_header_data.begin(), mh_len);
  if ( !m64 )
    mh.reserved = 0;

  mf = is_cigam(mh.magic);
  if ( mf )
    swap_mach_header_64(&mh);

  size_t size = mh_len + mh.sizeofcmds;
  if ( size > mach_size || size < mh_len ) // overflow?
    return false;
  mach_header_data.resize(size);
  if ( qlread(li, &mach_header_data[mh_len], mh.sizeofcmds) != mh.sizeofcmds )
  {
    mach_header_data.clear();
    return false;
  }

  return parse_load_commands(silent);
}

//--------------------------------------------------------------------------
bool macho_file_t::select_subfile(cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
  if ( fat_archs.empty() && set_subfile(0) )
  {
    // single file; check if it matches what we need
    if ( mh.cputype == cputype && (mh.cpusubtype == cpusubtype || cpusubtype == 0) )
      return true;
  }
  for ( size_t i = 0; i < fat_archs.size(); i++ )
  {
    // fat file; enumerate architectures
    const fat_arch &fa = fat_archs[i];
    if ( fa.cputype == cputype
      && (fa.cpusubtype == cpusubtype || cpusubtype == 0)
      && set_subfile(i) )
    {
      if ( mh.cputype == cputype && (mh.cpusubtype == cpusubtype || cpusubtype == 0) )
        return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// upon return: file position after at the beginning of the subfile
macho_file_t::subfile_type_t macho_file_t::get_subfile_type(uint n, size_t filesize)
{
  if ( !seek_to_subfile(n, filesize) )
    return SUBFILE_UNKNOWN;

  uint32_t magic;
  if ( qlread(li, &magic, sizeof(magic)) != sizeof(magic) )
    return SUBFILE_UNKNOWN;
  qlseek(li, -int(sizeof(magic)), SEEK_CUR);

  subfile_type_t type = SUBFILE_UNKNOWN;
  if ( magic == MH_CIGAM || magic == MH_MAGIC )
  {
    type = SUBFILE_MACH;
  }
  else if ( magic == MH_CIGAM_64 || magic == MH_MAGIC_64 )
  {
    type = SUBFILE_MACH_64;
  }
  else if ( strncmp(ARMAG, (const char *)&magic, sizeof(magic)) == 0 )
  {
    qoff64_t fpos = qltell(li);
    if ( is_ar_file(li, fpos, false) )
      type = SUBFILE_AR;
    qlseek(li, fpos, SEEK_SET);
  }

  return type;
}

//--------------------------------------------------------------------------
const mach_header_64 &macho_file_t::get_mach_header()
{
  QASSERT(20005, mach_offset != -1); // macho_file_t::get_mach_header: set_subfile() must be called first
  return mh;
}

//--------------------------------------------------------------------------
bool macho_file_t::parse_load_commands(bool silent)
{
  static bool complained = false;

  struct load_command l;
  const char *begin = (const char*)&mach_header_data[0];
  size_t delta = m64 ? sizeof(mach_header_64) : sizeof(mach_header);
  const struct load_command *lc = (load_command *)(begin + delta);

  const char *commands_end = begin + mach_header_data.size();
  begin = (const char*)lc;
  load_commands.clear();
  for ( uint32 i = 0; i < mh.ncmds && begin < commands_end; i++ )
  {
    if ( begin >= commands_end )
    {
      if ( !silent )
      {
        if ( !complained )
          warning("Inconsistent mh.ncmds %u, ignored extra commands", mh.ncmds);
        complained = true;
      }
      break;
    }
    safecopy(begin, commands_end, &l);
    if ( mf )
      swap_load_command(&l);
    if ( !silent && l.cmdsize % sizeof(int32) != 0 )
      msg("load command %u size not a multiple of 4\n", i);
    begin = (const char *)lc;
    const char *end = begin + l.cmdsize;
    if ( !silent && end > commands_end )
      msg("load command %u extends past end of load commands\n", i);
    if ( begin > end )
    {
      if ( !silent )
        warning("load command %u: cmdsize overflow", i);
      break;
    }
    if ( l.cmdsize == 0 )
    {
      if ( !silent )
        warning("load command %u size zero (can't advance to next load commands)", i);
      break;
    }
    load_commands.push_back(lc);
    begin = end;
    lc = (struct load_command *)begin;
  }
  if ( !silent && !complained && commands_end != begin )
  {
    warning("Inconsistent mh.sizeofcmds");
    complained = true;
  }

  parsed_section_info = false;
  return !load_commands.empty();
}

//--------------------------------------------------------------------------
#define HANDLE_SIMPLE_COMMAND(name)                       \
  {                                                       \
    name##_command cmd##name;                             \
    safecopy(begin, end, &cmd##name);                     \
    if ( mf )                                             \
      swap_##name##_command(&cmd##name);                  \
    result = v.visit_##name (&cmd##name, cmd_begin, end); \
  }

//--------------------------------------------------------------------------
template <class generic_segment_command, class generic_section>
int handle_lc_segment(const char *begin, const char *end, macho_lc_visitor_t &v, bool _mf)
{
  generic_segment_command sg;
  safecopy(begin, end, &sg);
  if ( _mf )
    swap_segment_command(&sg);
  const char *cmd_begin = begin;
  int result = v.visit_segment(&sg, cmd_begin, end);
  if ( result == 0 && sg.nsects > 0 )
  {
    generic_section s;
    for ( uint32_t j=0; j < sg.nsects; j++ )
    {
      if ( begin >= end )
      {
        static bool complained = false;
        if ( !complained )
          warning("Inconsistent number of sections %u in a segment", sg.nsects);
        complained = true;
        break;
      }
      cmd_begin = begin;
      safecopy(begin, end, &s);
      if ( _mf )
        swap_section(&s, 1);
      // ignore sections outside of the segment
      result = v.visit_section(&s, cmd_begin, end);
      if ( result != 0 )
        break;
    }
  }
  return result;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_load_commands(macho_lc_visitor_t &v)
{
  struct load_command l;
  int result = 0;
  const char *begin = (const char*)&mach_header_data[0], *end;
  const char *commands_end = begin + mach_header_data.size();

  for ( size_t i=0; result == 0 && i < load_commands.size(); i++ )
  {
    const struct load_command *lc = load_commands[i];
    l = *lc;
    if ( mf )
      swap_load_command(&l);
    begin = (const char*)lc;
    const char *cmd_begin = begin;
    end = begin + l.cmdsize;
    if ( end > commands_end || begin >= end )
      loader_failure("Inconsistency in load commands");
    result = v.visit_any_load_command(&l, cmd_begin, end);
    if ( result == 2 )
    {
      // don't call specific callback and continue
      result = 0;
      continue;
    }
    else if ( result != 0 )
    {
      // stop enumeration
      break;
    }
    switch ( l.cmd )
    {
      case LC_SEGMENT:
        result = handle_lc_segment<segment_command, section>(begin, end, v, mf);
        break;
      case LC_SEGMENT_64:
        result = handle_lc_segment<segment_command_64, section_64>(begin, end, v, mf);
        break;
      case LC_SYMTAB:
        HANDLE_SIMPLE_COMMAND(symtab);
        break;
      case LC_SYMSEG:
        HANDLE_SIMPLE_COMMAND(symseg);
        break;
      case LC_THREAD:
      case LC_UNIXTHREAD:
        HANDLE_SIMPLE_COMMAND(thread);
        break;
      case LC_IDFVMLIB:
      case LC_LOADFVMLIB:
        HANDLE_SIMPLE_COMMAND(fvmlib);
        break;
      case LC_IDENT:
        HANDLE_SIMPLE_COMMAND(ident);
        break;
      case LC_FVMFILE:
        HANDLE_SIMPLE_COMMAND(fvmfile);
        break;
      case LC_DYSYMTAB:
        HANDLE_SIMPLE_COMMAND(dysymtab);
        break;
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_ID_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LAZY_LOAD_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
        HANDLE_SIMPLE_COMMAND(dylib);
        break;
      case LC_ID_DYLINKER:
      case LC_LOAD_DYLINKER:
      case LC_DYLD_ENVIRONMENT:
        HANDLE_SIMPLE_COMMAND(dylinker);
        break;
      case LC_PREBOUND_DYLIB:
        HANDLE_SIMPLE_COMMAND(prebound_dylib);
        break;
      case LC_ROUTINES:
        HANDLE_SIMPLE_COMMAND(routines);
        break;
      case LC_SUB_FRAMEWORK:
        HANDLE_SIMPLE_COMMAND(sub_framework);
        break;
      case LC_SUB_UMBRELLA:
        HANDLE_SIMPLE_COMMAND(sub_umbrella);
        break;
      case LC_SUB_CLIENT:
        HANDLE_SIMPLE_COMMAND(sub_client);
        break;
      case LC_SUB_LIBRARY:
        HANDLE_SIMPLE_COMMAND(sub_library);
        break;
      case LC_TWOLEVEL_HINTS:
        HANDLE_SIMPLE_COMMAND(twolevel_hints);
        break;
      case LC_PREBIND_CKSUM:
        HANDLE_SIMPLE_COMMAND(prebind_cksum);
        break;
      case LC_ROUTINES_64:
        {
          routines_command_64 rc;
          safecopy(begin, end, &rc);
          if ( mf )
            swap_routines_command_64(&rc);
          result = v.visit_routines_64(&rc, cmd_begin, end);
        }
        break;
      case LC_UUID:
        HANDLE_SIMPLE_COMMAND(uuid);
        break;
      case LC_RPATH:
        HANDLE_SIMPLE_COMMAND(rpath);
        break;
      case LC_CODE_SIGNATURE:
      case LC_SEGMENT_SPLIT_INFO:
      case LC_FUNCTION_STARTS:
      case LC_DATA_IN_CODE:
      case LC_DYLIB_CODE_SIGN_DRS:
        HANDLE_SIMPLE_COMMAND(linkedit_data);
        break;
      case LC_ENCRYPTION_INFO:
        HANDLE_SIMPLE_COMMAND(encryption_info);
        break;
      case LC_ENCRYPTION_INFO_64:
        {
          encryption_info_command_64 ec;
          safecopy(begin, end, &ec);
          if ( mf )
            swap_encryption_info_command_64(&ec);
          result = v.visit_encryption_info_64(&ec, cmd_begin, end);
        }
        break;
      case LC_DYLD_INFO:
      case LC_DYLD_INFO_ONLY:
        HANDLE_SIMPLE_COMMAND(dyld_info);
        break;
      case LC_VERSION_MIN_MACOSX:
      case LC_VERSION_MIN_IPHONEOS:
      case LC_VERSION_MIN_WATCHOS:
        HANDLE_SIMPLE_COMMAND(version_min);
        break;
      case LC_MAIN:
        HANDLE_SIMPLE_COMMAND(entry_point);
        break;
      case LC_SOURCE_VERSION:
        HANDLE_SIMPLE_COMMAND(source_version);
        break;
      default:
        result = v.visit_unknown_load_command(&l, cmd_begin, end);
        break;
    }
  }
  return result != 0;
}

#define IS_PROTECTED(sg) ((sg.flags & SG_PROTECTED_VERSION_1) != 0 \
                        && sg.vmsize > 0 \
                        && (sg.fileoff > APPLE_UNPROTECTED_HEADER_SIZE \
                         || sg.fileoff + sg.filesize > APPLE_UNPROTECTED_HEADER_SIZE))

//--------------------------------------------------------------------------
inline bool is_protected(const segment_command &sg) { return IS_PROTECTED(sg); }
inline bool is_protected(const segment_command_64 &sg) { return IS_PROTECTED(sg); }

//--------------------------------------------------------------------------
int macho_file_t::is_encrypted()
{
  struct myvisitor: macho_lc_visitor_t
  {
    int is_encrypted;
    myvisitor(): is_encrypted(0) {}
    virtual int visit_segment(const struct segment_command *sg, const char *, const char *)
    {
      if ( is_protected(*sg) )
      {
        is_encrypted = 1;
        return 1;
      }
      return 0;
    }

    virtual int visit_segment(const struct segment_command_64 *sg, const char *, const char *)
    {
      if ( is_protected(*sg) )
      {
        is_encrypted = 1;
        return 1;
      }
      return 0;
    }

    virtual int visit_encryption_info(const struct encryption_info_command *ec, const char *, const char *)
    {
      if ( ec->cryptsize != 0 && ec->cryptid != 0 )
      {
        is_encrypted = 2;
        return 1;
      }
      return 0;
    }
    virtual int visit_encryption_info_64(const struct encryption_info_command_64 *ec, const char *, const char *)
    {
      if ( ec->cryptsize != 0 && ec->cryptid != 0 )
      {
        is_encrypted = 2;
        return 1;
      }
      return 0;
    }
  };

  myvisitor v;

  visit_load_commands(v);
  return v.is_encrypted;
}

//--------------------------------------------------------------------------
// check for LC_MAIN and/or LC_THREAD/LC_UNIXTHREAD commands
static void _get_thread_info(macho_file_t *mfile, const char **thr_begin, const char **thr_end, uint64_t *entryoff)
{
  struct ida_local myvisitor: macho_lc_visitor_t
  {
    const char *begin, *end;
    uint64_t entryoff;

    myvisitor(): begin(NULL), end(NULL), entryoff(0) {}

    virtual int visit_thread(const struct thread_command *, const char *_begin, const char *_end)
    {
      safeskip(_begin, _end, sizeof(thread_command));
      if ( _begin >= _end )
      {
        // bad command, try to continue
        return 0;
      }
      begin = _begin;
      end = _end;
      return 0;
    }

    //--------------------------------------------------------------------------
    virtual int visit_entry_point(const struct entry_point_command *ei, const char *_begin, const char *_end)
    {
      if ( !safeskip(_begin, _end, sizeof(entry_point_command)) )
      {
        // bad command
        return 0;
      }
      entryoff = ei->entryoff;
      return 0;
    }

  };

  myvisitor v;
  mfile->visit_load_commands(v);
  if ( thr_begin != NULL )
    *thr_begin = v.begin;
  if ( thr_end != NULL )
    *thr_end = v.end;
  if ( entryoff != NULL )
    *entryoff = v.entryoff;
}

//--------------------------------------------------------------------------
void macho_file_t::get_thread_state(const char *&begin, const char *&end)
{
  _get_thread_info(this, &begin, &end, NULL);
}

//--------------------------------------------------------------------------
uint64 macho_file_t::get_entry_address()
{
  const char *begin, *end;
  uint64_t entryoff;
  _get_thread_info(this, &begin, &end, &entryoff);
  if ( entryoff != 0 )
  {
    if ( base_addr == BADADDR64 )
      parse_section_info();
    return base_addr == BADADDR64 ? entryoff : base_addr + entryoff;
  }

  // no LC_MAIN, go the long way
  // fun fact: dyld does not check if the thread context actually has the correct flavor or even size
  // it just does stuff like:
  //   const i386_thread_state_t* registers = (i386_thread_state_t*)(((char*)cmd) + 16);
  //   void* entry = (void*)(registers->eip + fSlide);
  uint32 offset;
  switch ( mh.cputype )
  {
    case CPU_TYPE_POWERPC:
    case CPU_TYPE_POWERPC64:
    case CPU_TYPE_VEO:
      // __srr0 is at the start of the context
      offset = 0;
      break;
    case CPU_TYPE_ARM:
      offset = qoffsetof(arm_thread_state32_t, __pc);
      break;
    case CPU_TYPE_ARM64:
      offset = qoffsetof(arm_thread_state64_t, __pc);
      break;
    case CPU_TYPE_I386:
      offset = qoffsetof(i386_thread_state_t, __eip);
      break;
    case CPU_TYPE_X86_64:
      offset = qoffsetof(x86_thread_state64_t, __rip);
      break;
    default:
      // unhandled
      return BADADDR64;
  }
  // 8: skip flavor and count
  begin += 8 + offset;
  if ( m64 )
  {
    uint64 val;
    if ( !safecopy(begin, end, &val) )
      return BADADDR64;
    if ( mf )
      val = swap64(val);
    return val;
  }
  else
  {
    uint32 val;
    if ( !safecopy(begin, end, &val) )
      return BADADDR64;
    if ( mf )
      val = swap32(val);
    return val;
  }
}

//--------------------------------------------------------------------------
void macho_file_t::parse_section_info()
{
  /*
   * Create an array of section structures in the host byte sex so it
   * can be processed and indexed into directly.
   */

  struct myvisitor: macho_lc_visitor_t
  {
    secvec_t &sections;
    segcmdvec_t &segcmds;
    intvec_t &seg2section;
    bool m64;
    int32 nsecs_to_check;

    myvisitor(secvec_t &_sections, segcmdvec_t &_segcmds, intvec_t &seg2section_, bool _m64)
      : sections(_sections), segcmds(_segcmds), seg2section(seg2section_), m64(_m64), nsecs_to_check(0) {}

    virtual int visit_segment(const struct segment_command *sg, const char *, const char *)
    {
      if ( m64 )
      {
        warning("Found a 32-bit segment in 64-bit program, ignoring it");
        return 0;
      }
      else
      {
        segcmds.push_back(segment_to64(*sg));
        seg2section.push_back(sections.size());
        nsecs_to_check = sg->nsects;
      }
      return 0;
    }

    virtual int visit_segment(const struct segment_command_64 *sg, const char *, const char *)
    {
      if ( !m64 )
      {
        warning("Found a 64-bit segment in 32-bit program, ignoring it");
        return 0;
      }
      else
      {
        segcmds.push_back(*sg);
        seg2section.push_back(sections.size());
        nsecs_to_check = sg->nsects;
      }
      return 0;
    }

    bool check_section(const struct section_64 *s)
    {
      if ( --nsecs_to_check <= 0 ) // We have already visited all the sections of last good segment
        return true;
      const struct segment_command_64 &curseg = segcmds.back();
      if ( curseg.vmsize == 0 )
        return true;
      ea_t start = s->addr;
      ea_t end = s->addr+s->size;
      for ( int i = 0; i < sections.size(); i++ )
      {
        ea_t si_start = sections[i].addr;
        ea_t si_end = sections[i].addr + sections[i].size;
        if ( start > si_start && start < si_end
          || end > si_start && end < si_end )
        {
          warning("Section 0x%" FMT_64 "X of size %" FMT_64 "X intersects "
            "with existing section(0x%" FMT_64 "X, size %" FMT_64 "X). Skipped",
            s->addr, s->size, sections[i].addr, sections[i].size);
          return false;
        }
      }
      return true;
    }

    virtual int visit_section(const struct section *s, const char *, const char *)
    {
      section_64 s64 = section_to64(*s);
      if ( check_section(&s64) )
        sections.push_back(s64);
      return 0;
    }

    virtual int visit_section(const struct section_64 *s, const char *, const char *)
    {
      if ( check_section(s) )
        sections.push_back(*s);
      return 0;
    }
  };

  if ( !parsed_section_info )
  {
    mach_sections.clear();
    mach_segcmds.clear();
    seg2section.clear();
    myvisitor v(mach_sections, mach_segcmds, seg2section, m64);
    visit_load_commands(v);
    if ( !mach_segcmds.empty() )
    {
      segment_command_64 &sg = mach_segcmds[0];
      if ( streq(sg.segname, "__TEXT") && sg.fileoff != 0 )
      {
        // IDA assumes that the text segment is always at offset 0 - even for subfiles of FAT binaries and dyldcache files.
        // As of OSX10.13/iOS11, dyldcaches always use absolute offsets into the cache file, regardless of the segment.
        // In this case we must force the text segment to have offset 0 for the loader to work properly.
        // Also see the comment in dyld_single_macho_linput_t::read().
        // This is a band-aid. It must be fixed properly after the 7.0 release.
        sg.fileoff = 0;
      }
    }
    parsed_section_info = true;
    for ( size_t i = 0; i < mach_segcmds.size(); i++ )
    {
      const segment_command_64 &sg64 = mach_segcmds[i];
      if ( base_addr == BADADDR64 && sg64.fileoff == 0 && sg64.filesize != 0 )
      {
        base_addr = sg64.vmaddr;
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
const segcmdvec_t &macho_file_t::get_segcmds()
{
  parse_section_info();
  return mach_segcmds;
}

//--------------------------------------------------------------------------
const secvec_t &macho_file_t::get_sections()
{
  parse_section_info();
  return mach_sections;
}

//--------------------------------------------------------------------------
// get segment by index
bool macho_file_t::get_segment(size_t segIndex, segment_command_64 *pseg)
{
  parse_section_info();
  if ( segIndex < mach_segcmds.size() )
  {
    if ( pseg != NULL )
      *pseg = mach_segcmds[segIndex];
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// get section by segment index and virtual address inside section
bool macho_file_t::get_section(size_t segIndex, uint64_t vaddr, section_64 *psect)
{
  if ( segIndex < seg2section.size() )
  {
    const segment_command_64 &seg = mach_segcmds[segIndex];
    for ( size_t i = seg2section[segIndex]; i < seg2section[segIndex] + seg.nsects; i++ )
    {
      const section_64 &sect = mach_sections[i];
      if ( sect.addr <= vaddr && vaddr < sect.addr + sect.size )
      {
        if ( psect != NULL )
          *psect = sect;
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// find segment by name
bool macho_file_t::get_segment(const char *segname, segment_command_64 *pseg)
{
  parse_section_info();
  for ( size_t idx = 0; idx < mach_segcmds.size(); ++idx )
  {
    const segment_command_64 &seg = mach_segcmds[idx];
    if ( strncmp(seg.segname, segname, sizeof(seg.segname)) == 0 )
    {
      *pseg = seg;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// get section by segment name and section name
bool macho_file_t::get_section(const char *segname, const char *sectname, section_64 *psect)
{
  parse_section_info();
  for ( size_t idx = 0; idx < mach_segcmds.size(); ++idx )
  {
    const segment_command_64 &seg = mach_segcmds[idx];
    if ( strncmp(seg.segname, segname, sizeof(seg.segname)) == 0 )
    {
      for ( size_t i = seg2section[idx]; i < seg2section[idx] + seg.nsects; i++ )
      {
        QASSERT(20027, i < mach_sections.size());
        const section_64 &sect = mach_sections[i];
        if ( strncmp(sect.sectname, sectname, sizeof(sect.sectname)) == 0 )
        {
          if ( psect != NULL )
            *psect = sect;
          return true;
        }
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// get section's data by segment name and section name
bool macho_file_t::get_section(const char *segname, const char *sectname, bytevec_t *data)
{
  section_64 secthdr;
  if ( !get_section(segname, sectname, &secthdr) )
    return false;
  uint64 offset;
  if ( !is_mem_image() && mh.filetype == MH_OBJECT )
  {
    // we should use section's file offsets
    offset = secthdr.offset;
  }
  else
  {
    // we should use section's vaddr and use segment to find the corresponding file offset
    segment_command_64 seghdr;
    if ( !get_segment(segname, &seghdr) )
      return false;
    if ( is_mem_image() )
      offset = secthdr.addr - base_addr;
    else
      offset = seghdr.fileoff + (secthdr.addr - seghdr.vmaddr);
  }
  qlseek(li, start_offset + mach_offset + offset);
  data->resize(secthdr.size);
  qlread(li, data->begin(), secthdr.size);
  return true;
}

//--------------------------------------------------------------------------
const dyliblist_t macho_file_t::get_dylib_list(int kind)
{

  struct myvisitor: macho_lc_visitor_t
  {
    dyliblist_t &dylibs;
    int kind;

    myvisitor(dyliblist_t &_dylibs, int _kind): dylibs(_dylibs), kind(_kind) {}

    virtual int visit_dylib(const struct dylib_command *d, const char *begin, const char *end)
    {
      switch ( d->cmd )
      {
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB:
        case LC_LOAD_UPWARD_DYLIB:
          {
            // check if it's the kind of dylib we're looking for
            if ( kind != 0 && kind != d->cmd )
              return 0; // nope, continue
            // sanity check
            size_t off = d->dylib.name.offset;
            const char *namestart = begin + off;
            if ( off < sizeof(*d) || namestart < begin || namestart >= end )
            {
              dylibs.push_back("<bad dylib name>");
              break;
            }
            qstring dlname(namestart, end - namestart);
            dlname.rtrim('\0');
            dylibs.push_back(dlname);
          }
          break;
      }
      // continue enumeration
      return 0;
    }
  };

  if ( mach_dylibs.empty() || kind != 0 )
  {
    myvisitor v(mach_dylibs, kind);
    visit_load_commands(v);
    if ( kind != 0 )
    {
      dyliblist_t copy = mach_dylibs;
      mach_dylibs.clear();
      return copy;
    }
  }
  return mach_dylibs;
}

//--------------------------------------------------------------------------
const mod_table_t &macho_file_t::get_module_table()
{
  struct dysymtab_command dyst;

  if ( mach_modtable.empty() && get_dyst(&dyst) )
  {
    if ( dyst.modtaboff >= mach_size )
    {
      msg("module table offset is past end of file\n");
    }
    else
    {
      size_t entrysize = (m64 ? sizeof(struct dylib_module_64) : sizeof(struct dylib_module));
      size_t nmods = dyst.nmodtab;
      size_t size = nmods * entrysize;
      if ( dyst.modtaboff + size > mach_size )
      {
        msg("module table extends past end of file\n");
        size = mach_size - dyst.modtaboff;
        nmods = size / entrysize;
        size = nmods * entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.modtaboff);
      mach_modtable.resize(nmods);
      if ( m64 )
      {
        qlread(li, mach_modtable.begin(), size);
        if ( mf )
          swap_dylib_module_64(mach_modtable.begin(), nmods);
      }
      else
      {
        qvector<struct dylib_module> mods32;
        mods32.resize(nmods);
        qlread(li, mods32.begin(), size);
        dylib_module_to64(mods32.begin(), mach_modtable.begin(), nmods, mf);
      }
    }
  }
  return mach_modtable;
}

//--------------------------------------------------------------------------
const tocvec_t &macho_file_t::get_toc()
{
  struct dysymtab_command dyst;

  if ( mach_toc.empty() && get_dyst(&dyst) )
  {
    if ( dyst.tocoff >= mach_size )
    {
      msg("table of contents offset is past end of file\n");
    }
    else
    {
      size_t entrysize = sizeof(struct dylib_table_of_contents);
      size_t ntocs = dyst.ntoc;
      size_t size = ntocs * entrysize;
      if ( dyst.tocoff + size > mach_size )
      {
        msg("table of contents table extends past end of file\n");
        size = mach_size - dyst.tocoff;
        ntocs = size / entrysize;
        size = ntocs * entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.tocoff);
      mach_toc.resize(ntocs);
      qlread(li, mach_toc.begin(), size);
      if ( mf )
        swap_dylib_table_of_contents(mach_toc.begin(), ntocs);
    }
  }
  return mach_toc;
}

//--------------------------------------------------------------------------
const refvec_t &macho_file_t::get_ref_table()
{
  struct dysymtab_command dyst;

  if ( mach_reftable.empty() && get_dyst(&dyst) )
  {
    if ( dyst.extrefsymoff >= mach_size )
    {
      msg("reference table offset is past end of file\n");
    }
    else
    {
      size_t entrysize = sizeof(struct dylib_reference);
      size_t nrefs = dyst.nextrefsyms;
      size_t size = nrefs * entrysize;
      if ( dyst.extrefsymoff + size > mach_size )
      {
        msg("table of contents table extends past end of file\n");
        size = mach_size - dyst.extrefsymoff;
        nrefs = size / entrysize;
        size = nrefs * entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.extrefsymoff);
      mach_reftable.resize(nrefs);
      qlread(li, mach_reftable.begin(), size);
      if ( mf )
        swap_dylib_reference(&mach_reftable[0], nrefs);
    }
  }
  return mach_reftable;
}

//--------------------------------------------------------------------------
inline bool is_zeropage(const segment_command_64 &sg)
{
  return sg.vmaddr == 0 && sg.fileoff == 0 && sg.initprot == 0;
}

//--------------------------------------------------------------------------
inline bool is_text_segment(const segment_command_64 &sg)
{
  if ( is_zeropage(sg) )
    return false;
  const char *name = sg.segname;
  for ( int i=0; i < sizeof(sg.segname); i++, name++ )
    if ( *name != '_' )
      break;
  return strnicmp(name, "TEXT", 4) == 0;
}

//--------------------------------------------------------------------------
inline bool is_linkedit_segment(const segment_command_64 &sg)
{
  return strnicmp(sg.segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT)-1) == 0;
}

//--------------------------------------------------------------------------
// load chunk of data from the linkedit section
bool macho_file_t::load_linkedit_data(
        uint32 offset,
        size_t *size,
        void *buffer)
{
  if ( *size == 0 )
    return true;

  sval_t linkedit_shift = 0;
  if ( is_mem_image() )
  {
    // calculate shift between linkedit's segment file offset and memory address
    // so that we will seek to the correct address in memory
    for ( size_t i = 0; i < mach_segcmds.size(); i++ )
    {
      const segment_command_64 &sg64 = mach_segcmds[i];
      if ( base_addr == BADADDR64 && sg64.fileoff == 0 && sg64.filesize != 0 )
        base_addr = sg64.vmaddr;
      else if ( is_linkedit_segment(sg64) && linkedit_shift == 0 )
        linkedit_shift = sval_t(sg64.vmaddr - base_addr - sg64.fileoff);
    }
  }
  if ( offset >= mach_size )
    return false; // outside file
  if ( offset + *size > mach_size )
    *size = mach_size - offset;
  if ( *size == 0 )
    return false;
  qlseek(li, start_offset + mach_offset + linkedit_shift + offset);
  *size = qlread(li, buffer, *size);
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::get_uuid(uint8 uuid[16])
{
  struct ida_local uuid_getter_t : public macho_lc_visitor_t
  {
    uint8 *buf;
    bool retrieved;
    uuid_getter_t(uint8 *_buf) : buf(_buf), retrieved(false) {}
    virtual int visit_uuid(const struct uuid_command *cmnd,
                           const char *,
                           const char *)
    {
      memmove(buf, cmnd->uuid, 16);
      retrieved = true;
      return 0;
    }
  };
  uuid_getter_t uuid_getter(uuid);
  visit_load_commands(uuid_getter);
  return uuid_getter.retrieved;
}

//--------------------------------------------------------------------------
bool macho_file_t::match_uuid(const bytevec_t &bytes)
{
  if ( bytes.size() != 16 )
    return false;

  uint8 uuid[16];

  return get_uuid(uuid) && memcmp(uuid, bytes.begin(), sizeof(uuid)) == 0;
}

//--------------------------------------------------------------------------
bool macho_file_t::get_symtab_command(struct symtab_command *st)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct symtab_command *st;

    myvisitor(struct symtab_command *st_): st(st_) {}

    virtual int visit_symtab(const struct symtab_command *s, const char *, const char *)
    {
      *st = *s;
      return 1;
    }
  };

  myvisitor v(st);
  return visit_load_commands(v);
}

//--------------------------------------------------------------------------
void macho_file_t::get_symbol_table(
        const struct symtab_command &st,
        nlistvec_t *symbols)
{
  if ( st.symoff >= mach_size )
  {
    msg("WARNING: symbol table offset is past end of file\n");
  }
  else
  {
    size_t size = st.nsyms * (m64 ? sizeof(struct nlist_64) : sizeof(struct nlist));
    size_t nsymbols;
    size_t stend = st.symoff + size;
    if ( stend < st.symoff || stend > mach_size )
    {
      msg("WARNING: symbol table extends past end of file\n");
      size = mach_size - st.symoff;
      nsymbols = size / (m64 ? sizeof(struct nlist_64) : sizeof(struct nlist));
    }
    else
    {
      nsymbols = st.nsyms;
    }

    if ( nsymbols != 0 )
    {
      symbols->resize(nsymbols);
      struct nlist_64 *symbeg = symbols->begin();
      if ( m64 )
      {
        size = sizeof(struct nlist_64) * nsymbols;
        load_linkedit_data(st.symoff, &size, symbeg);
        if ( mf )
          swap_nlist_64(symbeg, symbeg, nsymbols);
      }
      else
      {
        qvector<struct nlist> syms32;
        syms32.resize(nsymbols);
        size = sizeof(struct nlist) * nsymbols;
        load_linkedit_data(st.symoff, &size, &syms32[0]);
        nlist_to64(&syms32[0], symbeg, nsymbols, mf);
      }
    }
  }
}

//--------------------------------------------------------------------------
void macho_file_t::get_string_table(
        const struct symtab_command &st,
        qstring *strings)
{
  if ( st.stroff >= mach_size )
  {
    msg("WARNING: string table offset is past end of file\n");
  }
  else
  {
    size_t strings_size;
    size_t stend = st.stroff + st.strsize;
    if ( stend < st.stroff || stend > mach_size )
    {
      msg("WARNING: string table extends past end of file\n");
      strings_size = mach_size - st.stroff;
    }
    else
    {
      strings_size = st.strsize;
    }

    string_table_waitbox_t wb(*this);

    for ( size_t off = 0; off < strings_size && !wb.cancelled(); )
    {
      size_t chunksize = qmin(32*1024, strings_size - off);
      strings->resize(strings->size()+chunksize);

      size_t newsize = chunksize;
      load_linkedit_data(st.stroff+off, &newsize, &strings->at(off));

      off += chunksize;
    }
  }
}

//--------------------------------------------------------------------------
void macho_file_t::get_symbol_table_info(nlistvec_t *symbols, qstring *strings)
{
  symbols->clear();
  strings->clear();

  struct symtab_command st = { 0 };
  if ( get_symtab_command(&st) )
  {
    get_symbol_table(st, symbols);
    get_string_table(st, strings);
  }
}

//--------------------------------------------------------------------------
bool macho_file_t::get_dyst(struct dysymtab_command *dyst)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct dysymtab_command *dyst;

    myvisitor(struct dysymtab_command *dyst_): dyst(dyst_)
    {
      dyst->cmd = 0;
    }

    virtual int visit_dysymtab(
        const struct dysymtab_command *s,
        const char *,
        const char *)
    {
      *dyst = *s;
      return 1;
    }
  };

  myvisitor v(dyst);
  return visit_load_commands(v);
}

//--------------------------------------------------------------------------
/*
 * get_indirect_symbol_table_info() returns indirect symbols. It handles the
 * problems related to the file being truncated and only returns valid info.
 * This routine may return misaligned pointers and it is up to
 * the caller to deal with alignment issues.
 */
void macho_file_t::get_indirect_symbol_table_info(qvector<uint32> *indirect_symbols)
{
  struct dysymtab_command dyst;

  indirect_symbols->clear();

  if ( !get_dyst(&dyst) )
    return;

  if ( dyst.indirectsymoff >= mach_size )
  {
    msg("indirect symbol table offset is past end of file\n");
  }
  else
  {
    size_t size = dyst.nindirectsyms * sizeof(uint32);
    size_t nindirect_symbols = dyst.nindirectsyms;
    if ( dyst.indirectsymoff + size > mach_size )
    {
      msg("indirect symbol table extends past end of file\n");
      size = mach_size - dyst.indirectsymoff;
      nindirect_symbols = size / sizeof(uint32);
      size = nindirect_symbols * sizeof(uint32);
    }
    indirect_symbols->resize(nindirect_symbols);
    qlseek(li, start_offset + mach_offset + dyst.indirectsymoff);
    qlread(li, indirect_symbols->begin(), size);
    if ( mf )
      swap_indirect_symbols(indirect_symbols->begin(), nindirect_symbols);
  }
}

//--------------------------------------------------------------------------
// load array of relocs from file with range checking and endianness swapping
bool macho_file_t::load_relocs(
        uint32 reloff,
        uint32 nreloc,
        relocvec_t *relocs,
        const char *desc)
{
  validate_array_count(NULL, &nreloc, sizeof(relocation_info), desc, reloff, mach_size);
  relocs->qclear();
  relocs->resize(nreloc);
  size_t size = nreloc * sizeof(relocation_info);
  qlseek(li, start_offset + mach_offset + reloff);
  if ( qlread(li, relocs->begin(), size) != size )
  {
    relocs->qclear();
    return false;
  }
  if ( mf )
    swap_relocation_info(relocs->begin(), nreloc);
  return true;
}

//--------------------------------------------------------------------------
void macho_file_t::visit_relocs(macho_reloc_visitor_t &v)
{
  if ( qgetenv("IDA_NORELOC") )
    return;

  struct dysymtab_command dyst;
  uint64 baseea = 0;
/*
  (from Mach-O spec)
 r_address
  In images used by the dynamic linker, this is an offset from the virtual memory address of the
  data of the first segment_command (page 20) that appears in the file (not necessarily the one
  with the lowest address). For images with the MH_SPLIT_SEGS flag set, this is an offset from
  the virtual memory address of data of the first read/write segment_command (page 20).
*/

  // we check for first writable segment if MH_SPLIT_SEGS is set
  // or on x64 (see ImageLoaderMachOClassic::getRelocBase() in dyld sources)
  // NB: in MH_KEXT_BUNDLE (processed by kernel kxld) r_address is still based on the first segment/0!

  bool need_writable = false;
  bool is_dyld_file = mh.filetype == MH_EXECUTE
                   || mh.filetype == MH_DYLINKER
                   || mh.filetype == MH_BUNDLE;
  if ( (mh.flags & MH_SPLIT_SEGS) != 0 || is_dyld_file && mh.cputype == CPU_TYPE_X86_64 )
  {
    need_writable = true;
  }
  for ( size_t i=0; i < mach_segcmds.size(); i++ )
  {
    if ( !need_writable
      || (mach_segcmds[i].initprot & (VM_PROT_WRITE|VM_PROT_READ)) == (VM_PROT_WRITE|VM_PROT_READ) )
    {
      baseea = mach_segcmds[i].vmaddr;
      break;
    }
  }

  relocvec_t relocs;
  if ( get_dyst(&dyst) && dyst.cmd != 0 )
  {
    // External relocation information
    uint32 nrelocs = dyst.nextrel;
    if ( nrelocs > 0 && load_relocs(dyst.extreloff, nrelocs, &relocs, "Number of dynamic external relocs") )
    {
      v.visit_relocs(baseea, relocs, macho_reloc_visitor_t::mach_reloc_external);
    }
    // Local relocation information
    nrelocs = dyst.nlocrel;
    if ( nrelocs > 0 && load_relocs(dyst.locreloff, nrelocs, &relocs, "Number of dynamic local relocs") )
    {
      v.visit_relocs(baseea, relocs, macho_reloc_visitor_t::mach_reloc_local);
    }
  }

  // Section relocation information
  for ( size_t i = 0; i < mach_sections.size(); i++ )
  {
    if ( mach_sections[i].nreloc == 0 )
      continue;

    char name[80];
    qsnprintf(name, sizeof(name), "Number of relocs for section (%.16s,%.16s)", mach_sections[i].segname, mach_sections[i].sectname);
    uint32 nrelocs = mach_sections[i].nreloc;
    if ( nrelocs > 0 && load_relocs(mach_sections[i].reloff, nrelocs, &relocs, name) )
    {
      v.visit_relocs(mach_sections[i].addr, relocs, i);
    }
  }
}

//--------------------------------------------------------------------------
bool macho_file_t::getSegInfo(uint64_t *segStartAddr, uint64_t *segSize, int segIndex)
{
  segment_command_64 seg;
  if ( !get_segment(segIndex, &seg) )
    return false;
  *segStartAddr = seg.vmaddr;
  *segSize = seg.vmsize;
  return true;
}

//--------------------------------------------------------------------------
static bool display_wrong_uleb(const uchar *p)
{
#ifdef EFD_COMPILE

  printf(
    "wrong uleb128/sleb128 encoding: %02X %02X %02X %02X %02X\n",
    p[0], p[1], p[2], p[3], p[4]);

#else

  deb(IDA_DEBUG_LDR,
    "wrong uleb128/sleb128 encoding: %02X %02X %02X %02X %02X\n",
    p[0], p[1], p[2], p[3], p[4]);

#endif

  return false;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_rebase_opcodes(const bytevec_t &data, dyld_info_visitor_t &v)
{
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  const uchar *p = begin;
  bool done = false;
  uint64_t ulebv, ulebv2;
  const int ptrsize = is64() ? 8 : 4;

  int segIndex;
  uint64_t segOffset = 0;
  uchar type = REBASE_TYPE_POINTER;
  uint64_t segStartAddr = BADADDR64;
  uint64_t segSize = BADADDR64;

  while ( !done && p < end )
  {
    uchar opcode = *p & REBASE_OPCODE_MASK;
    uchar imm    = *p & REBASE_IMMEDIATE_MASK;
    p++;
    switch ( opcode )
    {
      case REBASE_OPCODE_DONE:
        done = true;
        break;
      case REBASE_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        if ( !unpack_uleb128(&ulebv, &p, end) )
WRONG_ULEB:
          return display_wrong_uleb(p);
        segIndex = imm;
        segOffset = ulebv;
        segStartAddr = BADADDR64;
        segSize = BADADDR64;
        getSegInfo(&segStartAddr, &segSize, segIndex);
        break;
      case REBASE_OPCODE_ADD_ADDR_ULEB:
        {
          uint64 delta;
          if ( !unpack_uleb128(&delta, &p, end) )
            goto WRONG_ULEB;
          segOffset += delta;
        }
        break;
      case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        segOffset += imm * ptrsize;
        break;
      case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        if ( imm > segSize )
        {
          deb(IDA_DEBUG_LDR, "bad immediate value %02X in rebase info!\n", imm);
          return false;
        }
        if ( segStartAddr == BADADDR64 )
        {
WRONG_REBASE:
          msg("Wrong rebase info, file possibly corrupted!\n");
          return false;
        }
        for ( int i = 0; i < imm; i++ )
        {
          uint64 addr = segStartAddr + segOffset;
          if ( !is_loaded_addr(addr) )
            goto WRONG_REBASE;
          v.visit_rebase(addr, type);
          segOffset += ptrsize;
        }
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        if ( !unpack_uleb128(&ulebv, &p, end) )
          goto WRONG_ULEB;
        if ( ulebv > segSize )
          goto WRONG_ULEB;
        if ( segStartAddr == BADADDR64 )
          goto WRONG_REBASE;
        for ( size_t i = 0; i < ulebv; i++ )
        {
          uint64 addr = segStartAddr + segOffset;
          if ( !is_loaded_addr(addr) )
            goto WRONG_REBASE;
          v.visit_rebase(addr, type);
          segOffset += ptrsize;
        }
        break;
      case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        if ( !unpack_uleb128(&ulebv, &p, end) )
          goto WRONG_ULEB;
        v.visit_rebase(uint64_t(segStartAddr + segOffset), type);
        segOffset += ulebv + ptrsize;
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        if ( !unpack_uleb128(&ulebv, &p, end) )
          goto WRONG_ULEB;
        if ( !unpack_uleb128(&ulebv2, &p, end) )
          goto WRONG_ULEB;
        if ( ulebv > segSize || ulebv2 > segSize )
          goto WRONG_ULEB;
        if ( segStartAddr == BADADDR64 )
          goto WRONG_REBASE;
        for ( size_t i = 0; i < ulebv; i++ )
        {
          uint64 addr = segStartAddr + segOffset;
          if ( !is_loaded_addr(addr) )
            goto WRONG_REBASE;
          v.visit_rebase(addr, type);
          segOffset += ptrsize + ulebv2;
        }
        break;
      default:
        deb(IDA_DEBUG_LDR, "bad opcode %02X in rebase info!\n", opcode);
        return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_bind_opcodes(
        dyld_info_visitor_t::bind_kind_t bind_kind,
        const bytevec_t &data,
        dyld_info_visitor_t &v)
{
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  const uchar *p = begin;
  uint64 skip;
  uint64 count;
  const int ptrsize = is64() ? 8 : 4;

  int segIndex;
  char type = BIND_TYPE_POINTER;
  uchar flags = 0;
  uint64 libOrdinal = BIND_SPECIAL_DYLIB_SELF;
  int64_t addend = 0;
  const char *symbolName = NULL;
  uint64_t segStartAddr = BADADDR64;
  uint64_t segOffset = 0;
  uint64_t segSize = BADADDR64;

  bool done = false;
  while ( !done && p < end )
  {
    uchar opcode = *p & BIND_OPCODE_MASK;
    uchar imm    = *p & BIND_IMMEDIATE_MASK;
    p++;
    switch ( opcode )
    {
      case BIND_OPCODE_DONE:
        if ( bind_kind != dyld_info_visitor_t::bind_kind_lazy )
          done = true;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        libOrdinal = imm;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        if ( !unpack_uleb128(&libOrdinal, &p, end) )
WRONG_ULEB:
          return display_wrong_uleb(p);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        // the special ordinals are negative numbers
        if ( imm == 0 )
        {
          libOrdinal = 0;
        }
        else
        {
          int8_t signExtended = BIND_OPCODE_MASK | imm;
          libOrdinal = signExtended;
        }
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        flags = imm;
        symbolName = (const char*)p;
        while ( *p != '\0' )
          ++p;
        ++p;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        if ( !unpack_sleb128(&addend, &p, end) )
          goto WRONG_ULEB;
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        segIndex = imm;
        if ( !unpack_uleb128(&segOffset, &p, end) )
          goto WRONG_ULEB;
        segStartAddr = BADADDR64;
        segSize = BADADDR64;
        getSegInfo(&segStartAddr, &segSize, segIndex);
        break;
      case BIND_OPCODE_ADD_ADDR_ULEB:
        if ( !unpack_uleb128(&skip, &p, end) )
          goto WRONG_ULEB;
        segOffset += skip;
        break;
      case BIND_OPCODE_DO_BIND:
        {
          uint64 addr = segStartAddr + segOffset;
          v.visit_bind(bind_kind, addr, type, flags, libOrdinal, addend, symbolName);
          segOffset += ptrsize;
        }
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          uint64 addr = segStartAddr + segOffset;
          if ( !unpack_uleb128(&skip, &p, end) )
            goto WRONG_ULEB;
          v.visit_bind(bind_kind, addr, type, flags, libOrdinal, addend, symbolName);
          segOffset += skip + ptrsize;
        }
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          uint64 addr = segStartAddr + segOffset;
          skip = imm*ptrsize + ptrsize;
          v.visit_bind(bind_kind, addr, type, flags, libOrdinal, addend, symbolName);
          segOffset += skip;
        }
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        if ( !unpack_uleb128(&count, &p, end) )
          goto WRONG_ULEB;
        if ( !unpack_uleb128(&skip, &p, end) )
          goto WRONG_ULEB;
        if ( count > segSize || skip > segSize )
          goto WRONG_ULEB;
        {
          int i = 0;
          if ( symbolName != NULL && segStartAddr != BADADDR64 )
          {
            for ( ; i < count; i++ )
            {
              uint64 addr = segStartAddr + segOffset;
              if ( !is_loaded_addr(addr) )
              {
                msg("Warning: reference to wrong address %" FMT_64 "x\n", addr);
                break; // exported function must have initialized bytes
              }
              v.visit_bind(bind_kind, addr, type, flags, libOrdinal, addend, symbolName);
              segOffset += skip + ptrsize;
            }
          }
          segOffset += (count - i) * (skip + ptrsize);
        }
        break;
      default:
        msg("Warning: bad rebase opcode found (0x%02X), file possibly corrupted!\n", opcode);
        return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::processExportNode(
        const uchar *start,
        const uchar *p,
        const uchar *end,
        char *symname,
        int symnameoff,
        size_t symnamelen,
        dyld_info_visitor_t &v,
        int level)
{
  if ( symnameoff >= symnamelen || p >= end || p < start )
    return false;
  if ( level >= MAX_DEPTH )
    return false;
  const uchar terminalSize = unpack_db(&p, end);
  const uchar *children = p + terminalSize;
  if ( children >= end )
    return false;
  if ( terminalSize != 0 )
  {
    if ( symnameoff == 0 ) // no name??
      return false;
    uint64_t flags;
    uint64_t address;
    if ( !unpack_uleb128(&flags, &p, end) || !unpack_uleb128(&address, &p, end) )
      return display_wrong_uleb(p);
    if ( base_addr != BADADDR64 )
      address += base_addr;
    if ( v.visit_export(address, uint32(flags), symname) != 0 )
      return true;
  }
  const uchar childrenCount = unpack_db(&children, end);
  const uchar *s = children;
  for ( int i=0; i < childrenCount && s < end; ++i )
  {
    int edgeStrLen = 0;
    int maxlen = symnamelen - symnameoff;
    for ( uchar c = unpack_db(&s, end);
          c != '\0' && edgeStrLen < maxlen;
          ++edgeStrLen, c = unpack_db(&s, end) )
    {
      symname[symnameoff+edgeStrLen] = c;
    }
    if ( edgeStrLen >= maxlen )
      return false;
    if ( symnameoff == 0 && edgeStrLen == 0 ) // empty symbol??
      return false;
    symname[symnameoff+edgeStrLen] = '\0';
    uint64 ulebv;
    if ( !unpack_uleb128(&ulebv, &s, end) )
      return display_wrong_uleb(s);
    uint32_t childNodeOffset = (uint32_t)ulebv;
    if ( childNodeOffset == 0
      || childNodeOffset != ulebv
      || !processExportNode(start, start+childNodeOffset, end,
                            symname, symnameoff+edgeStrLen, symnamelen,
                            v, level+1) )
    {
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_export_info(const bytevec_t &data, dyld_info_visitor_t &v)
{
  char symname[MAXSTR*2];
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  symname[0] = '\0';
  if ( !processExportNode(begin, begin, end, symname, 0, sizeof(symname), v) )
  {
    warning("Bad information in exports, it will be ignored.");
    return false;
  }
  return true;
}


//--------------------------------------------------------------------------
void macho_file_t::visit_dyld_info(dyld_info_visitor_t &v)
{
  struct ida_local myvisitor: macho_lc_visitor_t
  {
    struct dyld_info_command *di;

    myvisitor(struct dyld_info_command *di_): di(di_)
    {
      di->cmd = 0;
    }

    virtual int visit_dyld_info(const struct dyld_info_command *lc, const char *, const char *)
    {
      *di = *lc;
      return 1;
    }
  };

  dyld_info_command di;
  myvisitor vdi(&di);
  if ( visit_load_commands(vdi) )
  {
    bytevec_t data;
    if ( di.rebase_size != 0 )
    {
      data.resize(di.rebase_size);
      size_t newsize = di.rebase_size;
      if ( load_linkedit_data(di.rebase_off, &newsize, &data[0]) && newsize != 0 )
        visit_rebase_opcodes(data, v);
      else
        msg("Error loading dyld rebase info\n");
    }
    if ( di.bind_size != 0 )
    {
      data.resize(di.bind_size);
      size_t newsize = di.bind_size;
      if ( load_linkedit_data(di.bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_normal, data, v);
      else
        msg("Error loading dyld bind info\n");
    }
    if ( di.weak_bind_size != 0 )
    {
      data.resize(di.weak_bind_size);
      size_t newsize = di.weak_bind_size;
      if ( load_linkedit_data(di.weak_bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_weak, data, v);
      else
        msg("Error loading dyld weak bind info\n");
    }
    if ( di.lazy_bind_size != 0 )
    {
      data.resize(di.lazy_bind_size);
      size_t newsize = di.lazy_bind_size;
      if ( load_linkedit_data(di.lazy_bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_lazy, data, v);
      else
        msg("Error loading dyld lazy bind info\n");
    }
    if ( di.export_size != 0 )
    {
      data.resize(di.export_size);
      size_t newsize = di.export_size;
      if ( load_linkedit_data(di.export_off, &newsize, &data[0]) && newsize != 0 )
        visit_export_info(data, v);
      else
        msg("Error loading dyld export info\n");
    }
  }
}

//--------------------------------------------------------------------------
void function_starts_visitor_t::handle_error()
{
  msg("Error loading function starts info\n");
}

//--------------------------------------------------------------------------
void macho_file_t::visit_function_starts(function_starts_visitor_t &v)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct linkedit_data_command *fs;

    myvisitor(struct linkedit_data_command *fs_): fs(fs_)
    {
      fs->cmd = 0;
    }

    virtual int visit_linkedit_data(const struct linkedit_data_command *lc, const char *, const char *)
    {
      if ( lc->cmd == LC_FUNCTION_STARTS )
      {
        *fs = *lc;
        return 1;
      }
      return 0;
    }
  };

  linkedit_data_command fs;
  myvisitor vfs(&fs);
  if ( visit_load_commands(vfs) && fs.datasize != 0 )
  {
    bytevec_t data;
    data.resize(fs.datasize);
    size_t newsize = fs.datasize;
    if ( !load_linkedit_data(fs.dataoff, &newsize, data.begin()) || newsize == 0 )
    {
      v.handle_error();
      return;
    }
    uint64_t address = base_addr != BADADDR64 ? base_addr : 0;
    const uchar *p = data.begin();
    const uchar *end = p + newsize;
    while ( p < end )
    {
      uint64_t delta;
      if ( !unpack_uleb128(&delta, &p, end) )
      {
        display_wrong_uleb(p);
        v.handle_error();
        return;
      }
      address += delta;
      v.visit_start(address);
    }
  }
}

//--------------------------------------------------------------------------
void macho_file_t::visit_shared_regions(shared_region_visitor_t &v)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct linkedit_data_command *sr;

    myvisitor(struct linkedit_data_command *sr_): sr(sr_)
    {
      sr->cmd = 0;
    }

    virtual int visit_linkedit_data(const struct linkedit_data_command *lc, const char *, const char *)
    {
      if ( lc->cmd == LC_SEGMENT_SPLIT_INFO )
      {
        *sr = *lc;
        return 1;
      }
      return 0;
    }
  };

  linkedit_data_command sr;
  myvisitor vsr(&sr);
  if ( visit_load_commands(vsr) && sr.datasize != 0 )
  {
    bytevec_t data;
    data.resize(sr.datasize);
    size_t newsize = sr.datasize;
    if ( !load_linkedit_data(sr.dataoff, &newsize, &data[0]) || newsize == 0 )
    {
      msg("Error loading segment split info\n");
      return;
    }
    uint64_t base = base_addr != BADADDR64 ? base_addr : 0;
    const uchar *p = &data[0];
    const uchar *end = p + data.size();
    while ( p < end )
    {
      uchar kind = unpack_db(&p, end);
      uint64_t address = 0;
      uint64_t delta;
      if ( !unpack_uleb128(&delta, &p, end) )
      {
WRONG_ULEB:
        display_wrong_uleb(p);
        return;
      }
      while ( p < end && delta != 0 )
      {
        address += delta;
        v.visit_region((shared_region_visitor_t::region_kind_t)kind, base + address);
        if ( !unpack_uleb128(&delta, &p, end) )
          goto WRONG_ULEB;
      }
    }
  }
}

//--------------------------------------------------------------------------
bool macho_file_t::get_id_dylib(qstring *id)
{
  struct myvisitor: macho_lc_visitor_t
  {
    qstring *dyld_id;
    bool found;
    myvisitor(qstring *_id): dyld_id(_id), found(false) {}

    int visit_dylib(const struct dylib_command *dl, const char *begin, const char *end)
    {
      if ( dl->cmd == LC_ID_DYLIB )
      {
        const char *p = begin + dl->dylib.name.offset;
        if ( p < end )
          *dyld_id = qstring(p, end-p);
        found = true;
        return 0;
      }
      return 1;
    }
  };

  if ( id == NULL )
    return false;
  myvisitor v(id);
  visit_load_commands(v);
  return v.found;
}

//--------------------------------------------------------------------------
/*const DYLDCache::ArchType DYLDCache::architectures[] =
{
  { CPU_TYPE_X86_64, CPU_SUBTYPE_MULTIPLE,  "dyld_v1  x86_64", "x86_64", littleEndian },
  { CPU_TYPE_X86, CPU_SUBTYPE_MULTIPLE,     "dyld_v1    i386", "i386", littleEndian },
  { CPU_TYPE_POWERPC, CPU_SUBTYPE_MULTIPLE, "dyld_v1     ppc", "rosetta", bigEndian },
  { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6,       "dyld_v1   armv6", "armv6", littleEndian },
  { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7,       "dyld_v1   armv7", "armv7", littleEndian },
  { CPU_TYPE_ARM64, CPU_SUBTYPE_MULTIPLE,   "dyld_v1   armv64","armv64", littleEndian },
  { 0 }
};*/

//--------------------------------------------------------------------------
bool dyld_cache_t::parse_header(uint32 flags)
{
  qlseek(li, 0);
  if ( qlread(li, &header, sizeof(header)) != sizeof(header) )
    return false;
  if ( !strneq(header.magic, "dyld_v", strlen("dyld_v")) )
    return false;
  if ( strneq(header.magic, "dyld_v0", strlen("dyld_v0")) )
    return false;

  const char *p = header.magic;
  // deduce endianness and bitness from the arch name
  p = tail(p);
  mf = streq(p - 3, "ppc");
  m64 = streq(p - 2, "64") || streq(p - 3, "64h"); // x86_64(h) or arm64
  if ( header.mappingOffset <= offsetof(dyld_cache_header, slideInfoOffset) )
  {
    // old format, without slide info
    header.slideInfoOffset = header.slideInfoSize = 0;
  }
  if ( header.mappingOffset <= offsetof(dyld_cache_header, islandsCount) )
  {
    // no island info
    header.islandsOffset = header.islandsCount = 0;
  }

  if ( (flags & PHF_MAPPINGS) != 0 )
  {
    if ( qlseek(li, header.mappingOffset) != header.mappingOffset )
      return false;
    mappings.resize(header.mappingCount);
    validate_array_count_or_die(li, header.mappingCount, sizeof(dyld_cache_mapping_info), "count of cache mapping infos");
    if ( qlread(li, mappings.begin(), sizeof(dyld_cache_mapping_info) * header.mappingCount) != sizeof(dyld_cache_mapping_info) * header.mappingCount )
      return false;
  }

  if ( (flags & PHF_IMAGES) != 0 )
  {
    if ( qlseek(li, header.imagesOffset) != header.imagesOffset )
      return false;
    image_infos.resize(header.imagesCount);
    validate_array_count_or_die(li, header.imagesCount, sizeof(dyld_cache_image_info), "count of images in the cache file");
    if ( qlread(li, image_infos.begin(), sizeof(dyld_cache_image_info) * header.imagesCount) != sizeof(dyld_cache_image_info) * header.imagesCount )
      return false;
    for ( size_t i = 0; i < header.imagesCount; i++ )
    {
      size_t name_off = image_infos[i].pathFileOffset;
      char namebuf[MAXSTR];
      if ( qlgetz(li, name_off, namebuf, sizeof(namebuf)) == NULL )
        return false;
      image_names.push_back(namebuf);
    }
  }

  if ( (flags & PHF_SYMBOLS) != 0 )
  {
    parse_local_symbols();
  }

  if ( (flags & PHF_ISLANDS) != 0 && header.islandsCount != 0 && header.islandsOffset != 0 )
  {
    if ( qlseek(li, header.islandsOffset) != header.islandsOffset )
      return false;
    validate_array_count(li, &header.islandsCount, sizeof(uint64), "branch islands entries count");
    island_addrs.resize(header.islandsCount);
    if ( qlread(li, island_addrs.begin(), sizeof(uint64) * header.islandsCount) != sizeof(uint64) * header.islandsCount )
      return false;
  }

  if ( (flags & PHF_SLIDE) != 0 && header.slideInfoOffset != 0 && header.slideInfoSize != 0 )
  {
    if ( qlseek(li, header.slideInfoOffset) != header.slideInfoOffset )
       return false;
    if ( qlread(li, &slide_version, sizeof(slide_version)) != sizeof(slide_version) )
      return false;
    if ( qlseek(li, header.slideInfoOffset) != header.slideInfoOffset )
      return false;

    if ( slide_version == 1 )
    {
      dyld_cache_slide_info si;
      if ( qlread(li, &si, sizeof(si)) != sizeof(si) )
        return false;

      slide_toc.resize(si.toc_count);
      if ( qlseek(li, header.slideInfoOffset + si.toc_offset) != header.slideInfoOffset + si.toc_offset )
        return false;
      validate_array_count_or_die(li, si.toc_count, sizeof(uint16), "Slide info TOC entries count");
      if ( qlread(li, slide_toc.begin(), sizeof(uint16) * si.toc_count) != sizeof(uint16) * si.toc_count )
        return false;

      slide_entries_size = si.entries_size;
      slide_entries.resize(si.entries_count*si.entries_size);
      if ( qlseek(li, header.slideInfoOffset + si.entries_offset) != header.slideInfoOffset + si.entries_offset )
        return false;
      if ( qlread(li, slide_entries.begin(), slide_entries.size()) != slide_entries.size() )
        return false;
    }
    else if ( slide_version == 2 )
    {
      dyld_cache_slide_info2 si;
      if ( qlread(li, &si, sizeof(si)) != sizeof(si) )
        return false;
      if ( si.page_size == 0 )
        return false;

      slide_page_size = si.page_size;
      slide_delta_mask = si.delta_mask;
      slide_value_add = si.value_add;

      slide_page_starts.resize(si.page_starts_count);
      if ( qlseek(li, header.slideInfoOffset + si.page_starts_offset) != header.slideInfoOffset + si.page_starts_offset )
        return false;
      validate_array_count_or_die(li, si.page_starts_count, sizeof(uint16), "Slide info page starts count");
      if ( qlread(li, slide_page_starts.begin(), sizeof(uint16) * si.page_starts_count) != sizeof(uint16) * si.page_starts_count )
        return false;

      slide_page_extras.resize(si.page_extras_count);
      if ( qlseek(li, header.slideInfoOffset + si.page_extras_offset) != header.slideInfoOffset + si.page_extras_offset )
        return false;
      validate_array_count_or_die(li, si.page_extras_count, sizeof(uint16), "Slide info page extras count");
      if ( qlread(li, slide_page_extras.begin(), sizeof(uint16) * si.page_extras_count) != sizeof(uint16) * si.page_extras_count )
        return false;
    }
  }

  return true;
}

//--------------------------------------------------------------------------
const char *dyld_cache_t::get_arch() const
{
  const char *p = strchr(header.magic, ' ');
  if ( p != NULL )
    while ( *p == ' ' )
      p++;
  return p;
}

//--------------------------------------------------------------------------
static int tzcnt(uint64 x)
{
  int b = 0;
  for ( ; x != 0 && (x & 1) == 0; x >>= 1 )
    b++;
  return b;
}

//--------------------------------------------------------------------------
bool dyld_cache_t::parse_slid_chain(dyld_cache_slide_visitor_t *v, uint64 start) const
{
  QASSERT(20104, slide_version == 2);

  uint64 off = 0;
  uint64 delta = 1;
  bool ok = true;

  while ( ok && delta != 0 && off < slide_page_size )
  {
    uint64 addr = start + off;
    uint64 raw_value = v->get_pointer_value(addr);
    if ( raw_value == BADADDR64 )
      break;

    ok = v->visit_pointer(addr, ~slide_delta_mask, slide_value_add) == 0;

    delta = (raw_value & slide_delta_mask) >> (tzcnt(slide_delta_mask)-2);
    off += delta;
  }

  return ok;
}

//--------------------------------------------------------------------------
bool dyld_cache_t::visit_slid_pointers(dyld_cache_slide_visitor_t *v)
{
  QASSERT(20068, mappings.size() > 1);

  bool ok = true;
  uint64 dataStartAddress = mappings[1].address;
  if ( slide_version == 1 )
  {
    size_t pagesize = slide_entries_size*8*4;
    for ( size_t i = 0, size = slide_toc.size(); ok && i < size; i++ )
    {
      size_t off = slide_toc[i] * slide_entries_size;
      if ( off >= slide_entries.size() )
        loader_failure("Corrupted DYLD slide info");
      const uchar *entry = &slide_entries[off];
      for ( size_t j = 0; ok && j < slide_entries_size; j++ )
      {
        uint64 page = dataStartAddress+i*pagesize;
        uchar  b = entry[j];
        if ( b != 0 )
        {
          for ( int k = 0; ok && k < 8; k++ )
          {
            if ( ((1u<<k) & entry[j]) != 0 )
              ok = v->visit_pointer(page+j*8*4+k*4, ~slide_delta_mask, slide_value_add) == 0;
          }
        }
      }
    }
  }
  else if ( slide_version == 2 )
  {
    for ( size_t i = 0; ok && i < slide_page_starts.size(); i++ )
    {
      uint64 page = dataStartAddress + (i * slide_page_size);

      uint16 start = slide_page_starts[i];
      if ( start == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE )
      {
        deb(IDA_DEBUG_LDR, "page %llx has no pointers for sliding\n", page);
        continue;
      }
      else if ( (start & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0 )
      {
        uint64 chain = page + (start * 4);
        deb(IDA_DEBUG_LDR, "page %llx: single slide chain at %llx\n", page, chain);
        ok = parse_slid_chain(v, chain);
      }
      else
      {
        for ( size_t j = start & 0x3FFF, size = slide_page_extras.size(); ok && j < size; j++ )
        {
          uint16 extra = slide_page_extras[j];
          if ( (extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END) != 0 )
            break;

          uint64 chain = page + (extra * 4);
          deb(IDA_DEBUG_LDR, "page %llx: extra slide chain at %llx\n", page, chain);
          ok = parse_slid_chain(v, chain);
        }
      }
    }
  }
  else
  {
    ok = false;
  }

  return ok;
}

//--------------------------------------------------------------------------
void dyld_cache_t::parse_local_symbols()
{
  if ( header.localSymbolsOffset == 0 || header.localSymbolsSize == 0 )
    return;

  if ( qlseek(li, header.localSymbolsOffset) != header.localSymbolsOffset )
    return;

  dyld_cache_local_symbols_info si;
  if ( qlread(li, &si, sizeof(si)) != sizeof(si) )
    return;

  nlistvec_t symbols;
  qstring strings;

  uint64_t symoff = header.localSymbolsOffset + si.nlistOffset;
  uint64_t stroff = header.localSymbolsOffset + si.stringsOffset;
  size_t nsymbols = si.nlistCount;

  size_t size = si.nlistCount * ( m64 ? sizeof(struct nlist_64) : sizeof(struct nlist) );
  uint64_t stend = symoff + size;
  uint64 mach_size = qlsize(li);
  if ( stend < symoff || stend > mach_size )
  {
    msg("WARNING: local symbol table extends past end of file\n");
    size = mach_size - symoff;
    nsymbols = size / ( m64 ? sizeof(struct nlist_64) : sizeof(struct nlist) );
  }

  if ( nsymbols != 0 )
  {
    symbols.resize(nsymbols);
    if ( m64 )
    {
      size = sizeof(struct nlist_64) * nsymbols;
      qlseek(li, symoff);
      qlread(li, &symbols[0], size);
      if ( mf )
        swap_nlist_64(&symbols[0], &symbols[0], nsymbols);
    }
    else
    {
      qvector<struct nlist> syms32;
      syms32.resize(nsymbols);
      size = sizeof(struct nlist) * nsymbols;
      qlseek(li, symoff);
      qlread(li, &syms32[0], size);
      nlist_to64(&syms32[0], &symbols[0], nsymbols, mf);
    }
  }
  if ( stroff >= mach_size )
  {
    msg("WARNING: string table offset is past end of file\n");
  }
  else
  {
    size_t strings_size;
    size_t strend = stroff + si.stringsSize;
    if ( strend < stroff || strend > mach_size )
    {
      msg("WARNING: string table extends past end of file\n");
      strings_size = mach_size - stroff;
    }
    else
    {
      strings_size = si.stringsSize;
    }

    strings.resize(strings_size);
    if ( strings_size != 0 )
    {
      qlseek(li, stroff);
      qlread(li, &strings[0], strings_size);
    }
  }
  localst_symbols = symbols;
  localst_strings = strings;

}

struct dyld_single_macho_linput_t : public generic_linput_t
{
  linput_t *li_dyld;
  qoff64_t region0_size;
  qoff64_t start_off;
  dyld_single_macho_linput_t(linput_t *li_dyld_, const dyld_cache_t &cache, const dyld_cache_image_info &ii)
    : li_dyld(li_dyld_)
  {

    // find the text (r-x) region

    dyld_cache_mapping_info mtext;
    bool found = false;
    for ( int i = 0; !found && i < cache.get_nummappings(); i++ )
    {
      const dyld_cache_mapping_info &mi = cache.get_mapping_info(i);
      if ( ( mi.maxProt & ( VM_PROT_EXECUTE | VM_PROT_READ ) ) == ( VM_PROT_EXECUTE | VM_PROT_READ ) )
      {
        mtext = mi;
        found = true;
      }
    }
    if ( !found )
    {
      ask_for_feedback("Read/execute region not found in the cache");
      loader_failure();
    }
    if ( cache.get_nummappings() >= 1 )
    {
      const dyld_cache_mapping_info &mLast = cache.get_mapping_info(cache.get_nummappings() - 1);
      region0_size = mtext.size;
      start_off = ii.address - mtext.address + mtext.fileOffset;
      filesize = mLast.fileOffset + mLast.size;
    }
    else
    {
      region0_size = 0;
      filesize = 0;
    }
    blocksize = 0; // don't cache
  }
  ssize_t idaapi read(qoff64_t off, void *buffer, size_t nbytes)
  {
    // offsets for the __TEXT segment are relative to the start of the r-x region
    // they fall into the first region of the cache file (read-only region)
    // the other parts (__DATA and __LINKEDIT) seem to use absolute offsets
    if ( off < region0_size )
      off += start_off;
    if ( qlseek(li_dyld, off, 0) != off )
      return -1;
    return qlread(li_dyld, buffer, nbytes);
  }
};


//--------------------------------------------------------------------------
linput_t *dyld_cache_t::create_single_macho_input(size_t imgindex) const
{
  if ( get_nummappings() < 1 )
    return NULL;
  QASSERT(20069, imgindex < image_infos.size());
  const dyld_cache_image_info &ii = get_image_info(imgindex);
  dyld_single_macho_linput_t *dsmli = new dyld_single_macho_linput_t(li, *this, ii);
  linput_t *dli = create_generic_linput(dsmli);
  return dli;
}

//--------------------------------------------------------------------------
linput_t *dyld_cache_t::create_single_island_input(size_t n) const
{
  if ( get_nummappings() < 1 )
    return NULL;
  dyld_cache_image_info ii;
  QASSERT(20070, n < island_addrs.size());
  ii.address = get_island_addr(n);
  dyld_single_macho_linput_t *dsmli = new dyld_single_macho_linput_t(li, *this, ii);
  linput_t *dli = create_generic_linput(dsmli);
  return dli;
}

// Object that will free an linput_t upon deletion
class linput_janitor_verbose_t
{
public:
  linput_janitor_verbose_t(linput_t *r, const qstring &filename): name(filename), resource(r)
  {
#if 0
    msg("got linput %s(%p)\n", name.c_str(), resource);
#endif
  }
  ~linput_janitor_verbose_t()
  {
#if 0
    msg("closing linput %s(%p)\n", name.c_str(), resource);
#endif
    close_linput(resource);
  }
private:
  qstring name;
  linput_t *resource;
};

//--------------------------------------------------------------------------
uint64 dyld_cache_t::find_exported_symbol(
        const char *_dylib,
        const char *symname,
        bool verbose) const
{
  if ( _dylib == NULL || _dylib[0] == '\0' || symname == NULL || symname[0] == '\0' )
    return BADADDR64;

  qstack<qstring> dylibs;
  dylibs.push(_dylib);
  linput_t *dlj = NULL;
  while ( !dylibs.empty() )
  {
    const qstring &dylibname = dylibs.pop();
    ssize_t j = get_image_index(dylibname);
    dlj = create_single_macho_input(j);
    QASSERT(1331, dlj != NULL);
    linput_janitor_verbose_t li_janitor(dlj, dylibname);
    macho_file_t mfile(dlj);
    if ( mfile.parse_header() && mfile.set_subfile(0) )
    {
      if ( verbose )
        msg("2 searching for symbol %s in %s\n", symname, dylibname.c_str());
      uint64 tmp = mfile.find_exported_symbol(symname, verbose, this);
      if ( tmp != BADADDR64 )
        return tmp;
    }
    // not found in this dylib; check linked reexported dylibs
    if ( (mfile.get_mach_header().flags & MH_NO_REEXPORTED_DYLIBS) == 0 )
    {
      dyliblist_t wlibs = mfile.get_dylib_list(LC_REEXPORT_DYLIB);
      for ( dyliblist_t::const_iterator p = wlibs.begin(); p != wlibs.end(); ++p )
      {
        if ( verbose )
          msg("2 checking reexported dylib %s for  %s\n", p->c_str(), dylibname.c_str());
        dylibs.add_unique(*p);
      }
    }
  }
  return BADADDR64;
}

//--------------------------------------------------------------------------
uint64 macho_file_t::find_exported_symbol(
        const char *symname,
        bool verbose,
        const dyld_cache_t *dcache)
{
  if ( symname == NULL || symname[0] == '\0' )
    return BADADDR64;

  // first try using dyld export info (which is faster and also handles tricky
  // reexported symbols like _memset)
  uint64 tmp = find_exported_symbol_dyld(symname, verbose, dcache);
  if ( tmp != BADADDR64 )
    return tmp;

  // else try the symtab approach

  bool arm32 = !m64 && get_mach_header().cputype == CPU_TYPE_ARM;
  qstring strings;
  nlistvec_t symbols;
  get_symbol_table_info(&symbols, &strings);
  size_t nsymbols = symbols.size();
  size_t strings_size = strings.size();
  for ( uint32 i = 0; i < nsymbols; i++ )
  {
    const struct nlist_64 &nl = symbols[i];
    int stype = nl.n_type & N_TYPE;
    if ( stype == N_UNDF || stype == N_PBUD )
      continue;
    if ( nl.n_un.n_strx >= strings_size )
      continue;
    const char *sname = &strings[nl.n_un.n_strx];
    if ( streq(symname, sname) )
    {
      uint64 v = nl.n_value;
      // add thumb bit if needed
      if ( arm32 && (nl.n_desc & N_ARM_THUMB_DEF) != 0 )
        v |= 1;
      return v;
    }
  }

  return BADADDR64;
}

//--------------------------------------------------------------------------
uint64 dyld_cache_t::find_exported_symbol_dyld(
        const char *_dylib,
        const char *symname,
        bool verbose) const
{
  if ( _dylib == NULL || _dylib[0] == '\0' || symname == NULL || symname[0] == '\0' )
    return BADADDR64;

  qstack<qstring> dylibs;
  dylibs.push(_dylib);
  linput_t *dlj = NULL;
  while ( !dylibs.empty() )
  {
    const qstring &dylibname = dylibs.pop();
    ssize_t j = get_image_index(dylibname);
    dlj = create_single_macho_input(j);
    QASSERT(1330, dlj != NULL);
    linput_janitor_verbose_t li_janitor(dlj, dylibname);
    macho_file_t mfile(dlj);
    if ( mfile.parse_header() && mfile.set_subfile(0) )
    {
      if ( verbose )
        msg("1 searching for symbol %s in %s\n", symname, dylibname.c_str());
      uint64 tmp = mfile.find_exported_symbol_dyld(symname, verbose, this);
      if ( tmp != BADADDR64 )
      {
        if ( verbose && dylibname != _dylib )
          msg("symbol '%s' found in dylib '%s', address: 0x%08" FMT_64"X\n",
            symname, dylibname.c_str(), tmp);
        return tmp;
      }
    }
    // not found in this dylib; check linked reexported dylibs
    dyliblist_t wlibs = mfile.get_dylib_list(LC_REEXPORT_DYLIB);
    for ( dyliblist_t::const_iterator p = wlibs.begin(); p != wlibs.end(); ++p )
    {
      if ( verbose )
        msg("1 checking reexported dylib %s for  %s\n", p->c_str(), dylibname.c_str());
      dylibs.add_unique(*p);
    }
  }
  return BADADDR64;
}

//--------------------------------------------------------------------------
uint64 macho_file_t::find_exported_symbol_dyld(
        const char *symname,
        bool verbose,
        const dyld_cache_t *dcache)
{
  if ( symname == NULL || symname[0] == '\0' )
    return BADADDR64;

  struct ida_local find_export_visitor_t : public macho_lc_visitor_t
  {
    macho_file_t &mfile;
    qstring symbol;
    const dyld_cache_t *dyldcache;
    uint64 expaddr;
    bool verbose;

    find_export_visitor_t(
        macho_file_t &_mfile,
        const char *_symbol,
        const dyld_cache_t *_dyldcache,
        bool _verbose)
      : mfile(_mfile),
        symbol(_symbol),
        dyldcache(_dyldcache),
        expaddr(-1),
        verbose(_verbose)
    {
    }
    virtual ~find_export_visitor_t() {}

    bool load_data(uint32_t offset, uint32_t size, bytevec_t &data)
    {
      if ( size == 0 )
        return false;
      data.resize(size);
      size_t newsize = size;
      if ( !mfile.load_linkedit_data(offset, &newsize, &data[0]) || newsize == 0 )
      {
        return false;
      }
      return true;
    }

    const uchar *trieWalk(const uchar *start, const uchar *end, const char *s) const
    {
      const uchar *p = start;
      bytevec_t visited;
      size_t len = end - start;
      visited.resize((len+7)/8, 0);

      uint32 nodeOffset = 0;
      while ( p != NULL )
      {
        if ( p >= end || p < start )
          return NULL;

        if ( visited.test_bit(nodeOffset) )
          return NULL; // endless loop
        visited.set_bit(nodeOffset);

        uint32_t terminalSize = unpack_db(&p, end);
        if ( terminalSize > 127 )
        {
          // except for re-export-with-rename, all terminal sizes fit in one byte
          --p;
          if ( !unpack_uleb128(&terminalSize, &p, end) )
            return NULL;
        }

        if ( *s == '\0' && terminalSize != 0 )
          return p;

        if ( p >= end || p < start )
          return NULL;
        const uchar *children = p + terminalSize;
        if ( children >= end || children < start )
          return NULL;
        uint8_t childrenRemaining = *children++;
        p = children;
        nodeOffset = 0;
        if ( p >= end || p < start )
          return NULL;
        for ( ; childrenRemaining > 0; --childrenRemaining )
        {
          const char *ss = s;
          bool wrongEdge = false;
          // scan whole edge to get to next edge
          // if edge is longer than target symbol name, don't read past end of symbol name
          char c = *p;
          while ( c != '\0' )
          {
            if ( !wrongEdge )
            {
              if ( c != *ss )
                wrongEdge = true;
              ++ss;
            }
            ++p;
            c = *p;
          }
          if ( wrongEdge )
          {
            // advance to next child
            ++p; // skip over zero terminator
                 // skip over uleb128 until last byte is found
            while ( ( *p & 0x80 ) != 0 )
              ++p;
            ++p; // skil over last byte of uleb128
          }
          else
          {
            // the symbol so far matches this edge (child)
            // so advance to the child's node
            ++p;
            if ( !unpack_uleb128(&nodeOffset, &p, end) )
              return NULL;
            s = ss;
            break;
          }
        }
        p = &start[nodeOffset];
      }
      return p;
    }

    bool process_export_info(const bytevec_t &data)
    {
      const uchar *begin = &data[0];
      const uchar *end = begin + data.size();
      const uchar *foundNodeStart = trieWalk(begin, end, symbol.c_str());
      if ( foundNodeStart == NULL )
        return false;
      const uchar *p = foundNodeStart;
      uint32 flags;
      if ( !unpack_uleb128(&flags, &p, end) )
        return false;
      if ( (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 )
      {
        // re-export from another dylib, lookup there
        if ( dyldcache == NULL )
        {
          if ( verbose )
            msg("symbol '%s' is reexported but can not follow without the dyld cache!\n", symbol.c_str() );
          return false;
        }
        uint32 ordinal;
        if ( !unpack_uleb128(&ordinal, &p, end) )
          return false;
        qstring importedName = (char*)p;
        if ( importedName[0] == '\0' )
          importedName = symbol;
        dyliblist_t dylibs = mfile.get_dylib_list();
        if ( ordinal > 0 && ordinal <= dylibs.size() )
        {
          const qstring &rdylib = dylibs[ordinal - 1];
          if ( verbose )
            msg("symbol '%s': looking up in reexported dylib '%s'\n", importedName.c_str(), rdylib.c_str());
          expaddr = dyldcache->find_exported_symbol(rdylib.begin(), importedName.begin(), verbose);
          if ( verbose )
            msg("symbol '%s' found in dylib '%s', address: 0x%08" FMT_64"X\n",
              importedName.c_str(), rdylib.c_str(), expaddr);
        }
      }
      else
      {
        if ( !unpack_uleb128(&expaddr, &p, end) )
          return false;
        expaddr += mfile.get_base();
      }

      return true;
    }

    virtual int visit_dyld_info(const struct dyld_info_command *lc, const char *, const char *)
    {
      bytevec_t data;
      if ( !load_data(lc->export_off, lc->export_size, data)
        || !process_export_info(data) )
      {
        expaddr = BADADDR64;
      }
      return 1;
    }
  };

  find_export_visitor_t v(*this, symname, dcache, verbose);
  visit_load_commands(v);
  return v.expaddr;
}

//------------------------------------------------------------------------
uint64 dyld_cache_t::read_addr_at_va(uint64 addr) const
{
  for ( size_t i = 0; i < mappings.size(); i++ )
  {
    const dyld_cache_mapping_info &m = mappings[i];
    if ( addr >= m.address )
    {
      uint64 off = addr - m.address;
      if ( off > m.size )
        continue;
      off += m.fileOffset;
      if ( qlseek(li, off, 0) != off )
        return BADADDR64;
      if ( m64 )
      {
        uint64 v;
        if ( qlread(li, &v, 8) != 8 )
          return BADADDR64;
        return v;
      }
      else
      {
        uint32 v;
        if ( qlread(li, &v, 4) != 4 )
          return BADADDR64;
        return v;
      }
    }
  }
  return BADADDR64;
}
