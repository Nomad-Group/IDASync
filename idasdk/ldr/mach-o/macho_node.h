#ifndef MACHO_NODE_H
#define MACHO_NODE_H

#define MACHO_NODE "$ macho" // supval(0) - mach_header

#define MACHO_ALT_IMAGEBASE nodeidx_t(-1) // image base of the input file
#define MACHO_ALT_UUID      nodeidx_t(-2) // uuid of the input file (supval)

#define CODE_TAG 'C' // charvals: code -> data rebase info
#define DATA_TAG 'D' // charvals: data -> code rebase info
#define SEGM_TAG 's' // hashvals: segm name -> segm start ea

#endif // MACHO_NODE_H
