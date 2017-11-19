#ifndef _OUTUTIL_HPP__
#define _OUTUTIL_HPP__

const color_t COLOR_NONE = 0;
#define WARN_SYM      ('#')

#define MIN_ARG_SIZE  3
#define STR_PRESERVED 64  // overlapped (MAXSTR*2) preservation (for color)

extern size_t outcnt;
extern bool no_prim;

int     out_commented(const char *p, color_t ntag = COLOR_NONE);
bool    change_line(bool main = false);
bool    checkLine(size_t size);
bool    chkOutLine(const char *str, size_t len);
#define CHK_OUT_STR(p)  chkOutLine(p, sizeof(p)-1)
static inline void OutKeyword(const char *str, size_t len)
    { outcnt += len; out_keyword(str); }
#define OUT_KEYWORD(p)  OutKeyword(p, sizeof(p)-1)
bool    chkOutKeyword(const char *str, uint len);
#define CHK_OUT_KEYWORD(p)  chkOutKeyword(p, sizeof(p)-1)
bool    chkOutSymbol(char c);
bool    chkOutChar(char c);
bool    chkOutSymSpace(char c);
static inline void outLine(const char *str, uint len)
    { outcnt += len; OutLine(str); }
#define OUT_STR(p)  outLine(p, sizeof(p)-1)
static inline uchar chkOutDot(void)
    { return chkOutChar('.'); }
static inline void OutSpace(void)
    { ++outcnt; OutChar(' '); }
static inline uchar chkOutSpace(void)
    { return chkOutChar(' '); }
uchar   putShort(ushort value, uchar wsym = WARN_SYM);
char    outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad);
uchar   putVal(const op_t &x, uchar mode, uchar warn);
uchar   OutUtf8(ushort index, fmt_t mode, color_t ntag = COLOR_NONE);
uchar   out_index(ushort index, fmt_t mode, color_t ntag, uchar as_index);
uchar   out_alt_ind(uint32 val);
void    out_method_label(uchar is_end);
uchar   outOffName(ushort off);
bool    block_begin(uchar off);
bool    block_end(uint32 off);
bool    block_close(uint32 off, const char *name);
bool    close_comment(void);
uchar   out_nodelist(uval_t nodeid, uchar pos, const char *pref);
void    init_prompted_output(char str[MAXSTR*2], uchar pos = 0);
void    term_prompted_output(void);
uchar   OutConstant(op_t& x, uchar impdsc = 0);
void    myBorder(void);
uchar   out_problems(char str[MAXSTR], const char *prefix);
uchar   putScope(ushort scope, uint32 doff);
size_t  debLine(void);

// in out.cpp
size_t  putDeb(uchar next);

#endif
