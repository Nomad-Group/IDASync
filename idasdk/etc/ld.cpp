/*

        *** For non-Unix systems ***

        This program calls bcc/vs linker command
        with correctly generated response file.

 ver    Created 25-Jun-95 by I. Guilfanov.

 2.0    adapted for BCC
 2.3    adapted for Visual Studio
 2.4    adapted for Windows CE
 2.5    Handle spaces in exe name
 2.6    Autoremove .exp (and .lib) files in VC mode
 2.8    Serialize calls to bcc linker

*/

#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <ctype.h>
#include <windows.h>

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

typedef unsigned char uchar;

char line[64*1024];

bool verbose  = true;
bool isbor    = false;        // borland style
bool isvc     = false;        // visual studio style
bool isce     = false;        // windows ce

HANDLE ilink32_mutex;

static char rspname[4096] = "rsptmp";

static void permutate(char *ptr, const char *user);
static int prc1(const char *file, const char *user); /* Process indirect file */
static int run(char *line, bool isvc);
/*------------------------------------------------------------------------*/
static char *strrpl(char *out, size_t outsize, const char *in, char s1, char s2)
{
  if ( int(outsize) <= 0 )
    abort();
  char *end = out + outsize;
  while ( true )
  {
    if ( out >= end )
    {
      out[-1] = '\0';
      break;
    }
    char s = *in++;
    if ( s == s1 )
      s = s2;
    *out = s;
    if ( s == '\0' )
      break;
    out++;
  }
  return out;
}

/*------------------------------------------------------------------------*/
static char *qstpncpy(char *out, const char *in, size_t outsize)
{
  return strrpl(out, outsize, in, 0, 0);
}

/*------------------------------------------------------------------------*/
inline char *dospath(char *out, const char *in, size_t outsize)
{
  return strrpl(out, outsize, in, '/', '\\');
}

/*------------------------------------------------------------------------*/
inline bool requires_quotes(const char *fname)
{
  if ( strchr(fname, ' ') != NULL )
    return true;
  if ( strchr(fname, '"') != NULL )
    return true;
  return false;
}

/*------------------------------------------------------------------------*/
static void copy_exe_name(const char *libexe)
{
  if ( requires_quotes(libexe) )
  {
    char *ptr = line;
    *ptr++ = '"';
    while ( *libexe )
    {
      char c = *libexe++;
      if ( c == '"' )
        *ptr++ = '\\';
      *ptr++ = c;
    }
    *ptr++ = '"';
    *ptr = '\0';
  }
  else
  {
    dospath(line, libexe, sizeof(line));
  }
  strcat(line, " ");
}

/*------------------------------------------------------------------------*/
static void remove_exp_and_lib(char *nargv[])
{
  char *opath = NULL;
  bool isdll = false;
  char *p;
  for( int i = 0; (p=nargv[i]) != NULL; i++ )
  {
    if ( *p == '-' || *p == '/' )
    {
      if ( stricmp(p+1, "ld") == 0 || stricmp(p+1, "dll") == 0 )
      {
        isdll = true;
        continue;
      }
      if ( p[1] == 'F' && p[2] == 'e' )
      {
        opath = p+3; // output path
        continue;
      }
    }
  }

  if ( opath != NULL )
  {
    p = strrchr(opath, '.') + 1;
    if ( p != NULL ) // just to please klocwork
    {
      strcpy(p, "exp");
      unlink(opath);
      if ( !isdll )
      {
        strcpy(p, "lib");
        unlink(opath);
      }
    }
  }
}

/*------------------------------------------------------------------------*/
static char *winerr(void)
{
  static char buf[1024];
  int code = GetLastError();
  if ( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                     NULL,
                     code,
                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     buf,
                     sizeof(buf),
                     NULL) )
  {
    strrpl(buf, sizeof(buf), buf, '\r', ' ');
    strrpl(buf, sizeof(buf), buf, '\n', ' ');
  }
  else
  {
    snprintf(buf, sizeof(buf), "Unknown error, code: 0x%08X", code);
  }
  return buf;
}

/*------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
  int code;
  int i;
  const char *linker = "wlink";
  char *user = NULL;
  char *toend = NULL;
  bool keep = false;

#define SW_CHAR '_'

  while ( argc > 1 && *argv[1] == SW_CHAR )
  {
    switch( argv[1][1] )
    {
      case 'b':
        isbor   = true;
        linker  = "tlink";
        break;
      case 'c':
        isce    = true;
        isvc    = true;
        linker  = "link";
        break;
      case 'l':
        linker = &argv[1][2];
        break;
      case 'k':
        keep    = true;
        break;
      case 'u':
        user    = &argv[1][2];
        if ( user[0] != '\0' ) break;
        goto usage;
      case 'v':
        isvc    = true;
        linker  = "link";
        break;
      case 'q':
        verbose = false;
        break;
      case 'a':
        if ( toend )
        {
          fprintf(stderr, "ld: only one 'a' switch is allowed\n");
          return 1;
        }
        toend = &argv[1][2];
        break;
      default:
usage:
        fprintf(stderr, "ld: illegal switch '%c'\n", argv[1][1]);
        return 1;
    }
    argc--;
    argv++;
  }

  if ( argc < 2 )
  {
    printf("ld version 2.8\n"
           "\tUsage: ld [%cl##] [%cb] [%cu...] ...\n"
           "\t %cv - visual studio style\n"
           "\t %cb - borland style\n"
           "\t %cc - wince style\n"
           "\t %cl - linker name\n"
           "\t %cu - user data\n"
           "\t %ca - append argument to end of command\n"
           "\t %ck - keep temporary file\n"
           "\t %cq - do not show command line\n",
           SW_CHAR, SW_CHAR, SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR,
           SW_CHAR);
    return 1;
  }

  copy_exe_name(linker);
  bool is_dll = false;
  char *end = line + sizeof(line);
  char *ptr = strchr(line, '\0');
  for ( i=1; i < argc; i++ )
  {
    if ( argv[i][0] == '@' )
    {
      static bool first = true;
      if ( !first )
      {
        fprintf(stderr, "ld: only one indirect file is allowed\n");
        return 1;
      }
      first = 0;
      code = prc1(&argv[i][1], user);
      if ( code != 0 )
        return code;
      ptr = qstpncpy(ptr, " @", end-ptr);
      ptr = dospath(ptr, rspname, end-ptr);
      continue;
    }
    ptr = qstpncpy(ptr, " ", end-ptr);
    bool quoted = false;
    if ( strchr(argv[i], ' ') != NULL )
    {
      ptr = qstpncpy(ptr, "\"", end-ptr);
      quoted = true;
    }
    if ( argv[i][0] == '/' )
      ptr = qstpncpy(ptr, argv[i], end-ptr);    // command line switch
    else
      ptr = dospath(ptr, argv[i], end-ptr);     // file name
    if ( quoted )
      ptr = qstpncpy(ptr, "\"", end-ptr);
    if ( isce && strcmp(argv[i], "/LD") == 0 )
      is_dll = true;
  }
  if ( toend && *toend )
  {
    strcat(line, " ");
    strcat(line, toend);
  }
  if ( isce )
  {
    if ( !is_dll )
    {
      if ( strstr(line, " /link ") == NULL )
        strcat(line, " /link ");
      strcat(line, " /entry:mainACRTStartup");
    }
  }
  if ( isbor )
  {
    static const char mutex_name[] = "ilink32_mutex";
    ilink32_mutex = CreateMutex(NULL, FALSE, mutex_name);
    if ( ilink32_mutex == NULL )
    {
      fprintf(stderr, "ld: failed to create %s: %s\n", mutex_name, winerr());
      return 1;
    }
    int code = WaitForSingleObject(ilink32_mutex, INFINITE);
    if ( code != WAIT_OBJECT_0 )
    {
      fprintf(stderr, "ld: failed to acquire ilink32_mutex (code=%d): %s\n", code, winerr());
      return 1;
    }
  }
  if ( verbose )
    printf("ld: %s\n", line);
  code = run(line, isvc);
  if ( isbor )
  {
    ReleaseMutex(ilink32_mutex);
    CloseHandle(ilink32_mutex);
  }
  if ( !keep )
    unlink(rspname);
  return code;
}

static char fl[4096];

/*------------------------------------------------------------------------*/
static int prc1(const char *file, const char *user) /* Process indirect file */
{
  FILE *fpo;
  FILE *fp = fopen(file, "r");
  if ( fp == 0 )
  {
    fprintf(stderr, "ld: can't open indirect file\n");
    return 1;
  }

  itoa(getpid(), strchr(rspname,0), 10);
  fpo = fopen(rspname, "w");
  if ( fpo == 0 )
  {
    fprintf(stderr, "ld: can't create temp file %s\n", rspname);
    fclose(fp);
    return 1;
  }
  while ( fgets(fl, sizeof(fl), fp) )
  {
    if ( strncmp(fl, "noperm", 6) == 0 )
    {
      fputs(fl+6, fpo);
      continue;
    }
    if ( strncmp(fl, "file", 4) == 0 || strncmp(fl, "lib", 3) == 0 )
    {
      char *ptr = fl;
      // skip word and spaces
      while ( *ptr != ' ' && *ptr != '\t' && *ptr != 0 )
        ptr++;
      while ( isspace(uchar(*ptr)) )
        ptr++;
      if ( user != NULL )
        permutate(ptr, user);
      fputs(ptr, fpo);
      continue;
    }
    if ( !isbor )
      fputs(fl, fpo);
  }
  fclose(fp);
  fclose(fpo);
  return 0;
}

/*---------------------------------------------------------------------*/
static int run(char *line, bool isvc)
{
  char *nargv[500];
  char *ptr = line;
  int i;
  for ( i=0; i < 500-1; i++ )
  {
    while ( *ptr == ' ' || *ptr == '\t' )
      ptr++;
    if ( *ptr == '\0' )
      break;
    if ( *ptr == '"' || *ptr == '\'' )
    {
      nargv[i] = ptr;
      char lim = *ptr++;
      while ( *ptr != lim && *ptr != '\0' )
      {
        if ( *ptr == '\\' && (*ptr == '"' || *ptr == '\'') )
          memmove(ptr, ptr+1, strlen(ptr));
        ptr++;
      }
      if ( *ptr == lim )
        ptr++;
    }
    else
    {
      nargv[i] = ptr;
      while ( *ptr != ' ' && *ptr != '\t' && *ptr != '\0' )
        ptr++;
    }
    if ( *ptr != '\0' )
      *ptr++ = '\0';
  }
  nargv[i] = NULL;

  i = spawnvp(P_WAIT, nargv[0], nargv);
  if ( i != 0 )
  {
    if ( i == -1 )
      perror("exec error");
    else
      printf("ld error: '%s' exit with code %d\n", nargv[0], i);
    return 3;
  }
  else if ( isvc )
  {
    remove_exp_and_lib(nargv);
  }
  return 0;
}

/*------------------------------------------------------------------------*/
static int extract_words(const char *ptr, char **words, int maxwords)
{
  int n = 0;
  while ( true )
  {
    const char *beginning;
    while ( isspace(uchar(*ptr)) )
      ptr++;
    if ( *ptr == 0 )
      break;
    if ( n >= maxwords )
    {
      fprintf(stderr, "ld: too many words for permutation\n");
      exit(1);
    }
    beginning = ptr;
    while ( !isspace(*ptr) && *ptr != 0 )
      ptr++;
    size_t len = ptr - beginning;
    words[0] = (char *)malloc(len+1);
    memcpy(words[0], beginning, len);
    words[0][len] = 0;
    words++;
    n++;
  }
  return n;
}

/*------------------------------------------------------------------------*/
static void permutate(char *ptr, const char *user)
{
  int i;
#define MAX_WORDS 1024
  char *words[MAX_WORDS];
  int n = extract_words(ptr, words, MAX_WORDS);

  // the last 'const_files' files will not be permutated
  int const_files = 0;
  if ( n > 0 && strnicmp(words[n-1], "cw32", 4) == 0 )
    const_files = 1;

  const char *ud = user;
  for ( i=0; i < n; i++ )
  {
    int idx = i;
    if ( i < n-const_files )
    {
      char x = *ud++;
      if ( x == 0 )
      {
        ud = user;
        x = *ud++;
      }
      idx = (unsigned char)(x) % (n-const_files-i);
    }
    // output space between words
    if ( i != 0 )
      *ptr++ = ' ';
    // output the selected word
    ptr = strcpy(ptr, words[idx]);
    ptr = strchr(ptr, '\0');
    // delete the used word
    free(words[idx]);
    memmove(&words[idx], &words[idx+1], sizeof(char*)*(n-idx-1));
  }
  *ptr++ = '\n';
  *ptr = 0;
}

