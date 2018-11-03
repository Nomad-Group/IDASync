/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _CONFIG_HPP
#define _CONFIG_HPP




//-----------------------------------------------------------------------
/// \defgroup IDPOPT_T Option value types
/// Passed as 'value_type' parameter to ::set_options_t callbacks
//@{
#define IDPOPT_STR 1    ///< string constant (char *)
#define IDPOPT_NUM 2    ///< number (uval_t *)
#define IDPOPT_BIT 3    ///< bit, yes/no (int *)
#define IDPOPT_I64 5    ///< 64bit number (int64 *)
#define IDPOPT_CST 6    ///< lexer (lexer_t*)
                        ///< Custom type, starting with a '{'
                        ///< Values of this type should be handled by
                        ///< ::set_options_t callbacks. E.g.,:
                        ///< \code
                        ///< ERROR_STRINGS =
                        ///< {
                        ///<   {0, "Unknown error"},
                        ///<   {1, "Missing filename"},
                        ///<   {5, "Out-of-memory"}
                        ///< }
                        ///< \endcode
                        ///< For values of this type, the data that will
                        ///< be passed as the callback's 'value' parameter
                        ///< is the lexer instance that is being used
                        ///< to parse the configuration file.
                        ///< You can use \ref parse_json() (see parsejson.hpp)
                        ///< to parse JSON-format data
                        ///< NB: the '{' is already consumed by the parser,
                        ///< so you need to push it again if it's a part of the JSON object
//@}

/// \defgroup IDPOPT_RET Option result codes
/// Predefined return values for ::set_options_t callbacks
//@{
#define IDPOPT_OK       NULL            ///< ok
#define IDPOPT_BADKEY   ((char*)1)      ///< illegal keyword
#define IDPOPT_BADTYPE  ((char*)2)      ///< illegal type of value
#define IDPOPT_BADVALUE ((char*)3)      ///< illegal value (bad range, for example)
//@}


/// Callback - called when a config directive is processed in IDA.
/// Also see read_config_file() and processor_t::set_idp_options
/// \param keyword     keyword encountered in IDA.CFG/user config file.
///                    if NULL, then an interactive dialog form should be displayed
/// \param value_type  type of value of the keyword - one of \ref IDPOPT_T
/// \param value       pointer to value
/// \return one of \ref IDPOPT_RET, otherwise a pointer to an error message

typedef const char *(idaapi set_options_t)(
        const char *keyword,
        int value_type,
        const void *value);

/// \defgroup IDAOPT_PRIO Option priority
/// Not used yet in processor modules but is used in debugger (idd.hpp).
/// Normally default priority option does not overwrite existing value whereas
/// high priority one does.
/// High priority options may be stored in the database to be available
/// in the next session
//@{
#define IDPOPT_PRI_DEFAULT 1  ///< default priority - taken from config file
#define IDPOPT_PRI_HIGH    2  ///< high priority - received from UI or script function
//@}


//-------------------------------------------------------------------------
/// Parse the value type for the value token 'value'.
/// This is mostly used for converting from values that a cfgopt_handler_t
/// receives, into data that callbacks
///  - processor_t::set_idp_options
///  - debugger_t::set_dbg_options
/// expect.
///
/// Plugins that wish to use options shouldn't rely on this,
/// and use the cfgopt_t utility instead.
///
/// \param out parsed data
/// \param lx the lexer in use
/// \param value the value token
/// \return true if guessing didn't lead to an error, false otherwise.
///         note that even if 'true' is returned, it doesn't mean the
///         type could be guessed: merely that no syntax error occured.
class lexer_t;
struct token_t;
idaman bool ida_export parse_config_value(
        idc_value_t *out,
        lexer_t *lx,
        const token_t &value);

//-------------------------------------------------------------------------
typedef const char *(idaapi cfgopt_handler_t)(
        lexer_t *lx,
        const token_t &keyword,
        const token_t &value);

//-----------------------------------------------------------------------
/// used by cfgopt_t. You shouldn't have to deal with those directly.
#define IDPOPT_NUM_INT     (0)
#define IDPOPT_NUM_CHAR    (1 << 24)
#define IDPOPT_NUM_SHORT   (2 << 24)
#define IDPOPT_NUM_RANGE   (1 << 26)
#define IDPOPT_NUM_UNS     (1 << 27)

#define IDPOPT_BIT_UINT    0
#define IDPOPT_BIT_UCHAR   (1 << 24)
#define IDPOPT_BIT_USHORT  (2 << 24)
#define IDPOPT_BIT_BOOL    (3 << 24)
#define IDPOPT_BIT_INVRES  (1 << 26)

#define IDPOPT_STR_QSTRING (1 << 24)
#define IDPOPT_STR_LONG    (1 << 25)

#define IDPOPT_I64_RANGES  (1 << 24)
#define IDPOPT_I64_UNS     (1 << 25)

//-------------------------------------------------------------------------
struct cfgopt_t;
idaman const char *ida_export cfgopt_t__apply(
        const cfgopt_t *_this,
        int vtype,
        const void *vdata);

//-------------------------------------------------------------------------
// cfgopt_t objects are suitable for being statically initialized, and
// passed to 'read_config_file'.
//
// E.g.,
// ---
// static const cfgopt_t g_opts[] =
// {
//   cfgopt_t("AUTO_UNDEFINE", &auto_undefine, -1, 1),
//   cfgopt_t("NOVICE", &novice, true),
//   cfgopt_t("EDITOR", editor_buf, sizeof(editor_buf)),
//   cfgopt_t("SCREEN_PALETTE", set_screen_palette), // specific handler for SCREEN_PALETTE
// };
//
// ...
//
// read_config_file("myfile", g_opts, qnumber(g_opts), other_handler)
// ---
//
// NOTES:
//   * so-called 'long' strings (the default) can span on multiple lines,
//     and are terminated by a ';'
struct cfgopt_t
{
  const char *name;
  void *ptr;
  int flags;
  union
  {
    size_t buf_size;
    struct
    {
      int64 min;
      int64 max;
    } num_range;
    uint32 bit_flags;
  };

  // IDPOPT_STR
  cfgopt_t(const char *_n, char *_p, size_t _sz, bool _long = true)
    : name(_n), ptr(_p), flags(IDPOPT_STR | (_long ? IDPOPT_STR_LONG : 0))
  { buf_size = _sz; }
  cfgopt_t(const char *_n, qstring *_p, bool _long = true)
    : name(_n), ptr(_p), flags(IDPOPT_STR | IDPOPT_STR_QSTRING | (_long ? IDPOPT_STR_LONG : 0))
  {}

  // IDPOPT_NUM
  cfgopt_t(const char *_n, int *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM) {}
  cfgopt_t(const char *_n, uint *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS) {}
  cfgopt_t(const char *_n, char *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_CHAR) {}
  cfgopt_t(const char *_n, uchar *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_CHAR) {}
  cfgopt_t(const char *_n, short *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_SHORT) {}
  cfgopt_t(const char *_n, ushort *_p)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_SHORT) {}
  // IDPOPT_NUM + ranges
  cfgopt_t(const char *_n, int *_p, int _min, int _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_RANGE) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, uint *_p, uint _min, uint _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_RANGE) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, char *_p, char _min, char _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_CHAR | IDPOPT_NUM_RANGE) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, uchar *_p, uchar _min, uchar _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_CHAR | IDPOPT_NUM_RANGE) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, short *_p, short _min, short _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_RANGE | IDPOPT_NUM_SHORT) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, ushort *_p, ushort _min, ushort _max)
    : name(_n), ptr(_p), flags(IDPOPT_NUM | IDPOPT_NUM_UNS | IDPOPT_NUM_RANGE | IDPOPT_NUM_SHORT) { num_range.min = _min; num_range.max = _max; }

  // IDPOPT_BIT
  cfgopt_t(const char *_n, bool *_p, bool _flags, const int *optflgs = NULL) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_BOOL) { bit_flags = _flags; if ( optflgs != NULL ) flags |= *optflgs; }
  cfgopt_t(const char *_n, uchar *_p, uchar _flags, const int *optflgs = NULL) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_UCHAR) { bit_flags = _flags; if ( optflgs != NULL ) flags |= *optflgs; }
  cfgopt_t(const char *_n, ushort *_p, ushort _flags, const int *optflgs = NULL) : name(_n), ptr(_p), flags(IDPOPT_BIT | IDPOPT_BIT_USHORT) { bit_flags = _flags; if ( optflgs != NULL ) flags |= *optflgs; }
  cfgopt_t(const char *_n, uint32 *_p, uint32 _flags, const int *optflgs = NULL) : name(_n), ptr(_p), flags(IDPOPT_BIT) { bit_flags = _flags; if ( optflgs != NULL ) flags |= *optflgs; }

  // IDPOPT_I64
  cfgopt_t(const char *_n, int64 *_p) : name(_n), ptr(_p), flags(IDPOPT_I64) {}
  cfgopt_t(const char *_n, uint64 *_p) : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_NUM_UNS) {}
  // IDPOPT_I64 + ranges
  cfgopt_t(const char *_n, int64 *_p, int64 _min, int64 _max)
    : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_I64_RANGES) { num_range.min = _min; num_range.max = _max; }
  cfgopt_t(const char *_n, uint64 *_p, uint64 _min, uint64 _max)
    : name(_n), ptr(_p), flags(IDPOPT_I64 | IDPOPT_I64_UNS | IDPOPT_I64_RANGES) { num_range.min = _min; num_range.max = _max; }

  // IDPOPT_CST
  cfgopt_t(const char *_n, cfgopt_handler_t *_p) : name(_n), ptr((void *) _p), flags(IDPOPT_CST) {}

  int type() const { return flags & 0xf; }
  int qualifier() const { return flags & 0xf000000; }

  const char *apply(int vtype, const void *vdata) const { return cfgopt_t__apply(this, vtype, vdata); }
};

/// Parse the input, and apply options.
///
/// \param input      input file name, or string
/// \param is_file    is input a string, or a file name
/// \param opts       options destcriptions
/// \param nopts      the number of entries present in the 'opts' array
/// \param defhdlr    a handler to be called, if a directive couldn't be found in 'opts'
/// \param defines    a list of preprocessor identifiers to define (so it is
///                   possible to use #ifdef checks in the file.)
///                   NB: the actual identifier defined by the parser will be
///                   surrounded with double underscores (e.g., passing 'FOO'
///                   will result in '__FOO__' being defined)
///                   Additionally, the parser will also define a similar macro
///                   with the current processor name (e.g., __ARM__)
/// \param ndefines   the number of defines in the list
/// \return true if parsing finished without errors, false if there was a
///         syntax error, callback returned an error, or no file was found
///         at all.

idaman bool ida_export read_config(
        const char *input,
        bool is_file,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr = NULL,
        const char *const *defines = NULL,
        size_t ndefines = 0);


/// Search for all IDA system files with the given name.
/// This function will search, in that order, for the following files:
///   -# %IDADIR%/cfg/<file>
///   -# for each directory 'ONEDIR' in %IDAUSR%: %ONEDIR%/cfg/<file>
///
/// For each directive in each of those files, the same processing as
/// that of read_config will be performed.

inline bool read_config_file(
        const char *filename,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr = NULL,
        const char *const *defines = NULL,
        size_t ndefines = 0)
{
  return read_config(filename, true, opts, nopts, defhdlr, defines, ndefines);
}


/// For each directive in 'string', the same processing as that of
/// read_config will be performed.
inline bool read_config_string(
        const char *string,
        const cfgopt_t opts[],
        size_t nopts,
        cfgopt_handler_t *defhdlr = NULL,
        const char *const *defines = NULL,
        size_t ndefines = 0)
{
  return read_config(string, false, opts, nopts, defhdlr, defines, ndefines);
}


/// Get one of config parameters defined by CC_PARMS in ida.cfg.
/// All parameters for all compilers are stored in local map during last read
/// of ida.cfg - this function just returns previously stored parameter value for
/// given compiler (NULL if no such parameter)
idaman const char *ida_export cfg_get_cc_parm(comp_t compid, const char *name);


/// Get header path config parameter from ida.cfg.
/// Also see cfg_get_cc_parm()

inline const char *cfg_get_cc_header_path(comp_t compid)
{
  return cfg_get_cc_parm(compid, "HEADER_PATH");
}


/// Get predefined macros config parameter from ida.cfg.
/// Also see cfg_get_cc_parm()

inline const char *cfg_get_cc_predefined_macros(comp_t compid)
{
  return cfg_get_cc_parm(compid, "PREDEFINED_MACROS");
}



#endif // _CONFIG_HPP
