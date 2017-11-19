//--------------------------------------------------------------------------
// hex place methods

typedef hex_place_t   hp_t;

//--------------------------------------------------------------------------
// Short information about the current location.
// It will be displayed in the status line
void ida_export hex_place_t__print(const hp_t *, void *, char *buf, size_t bufsize)
{
  if ( bufsize != 0 )
    buf[0] = 0;
}

//--------------------------------------------------------------------------
// Convert current location to 'uval_t'
uval_t ida_export hex_place_t__touval(const hp_t *ths, void *)
{
  return ths->n;
}

//--------------------------------------------------------------------------
// Make a copy
place_t *ida_export hex_place_t__clone(const hp_t *ths)
{
  hp_t *p = qnew(hp_t);
  if ( p == NULL )
    nomem("simpleline_place");
  memcpy(p, ths, sizeof(*ths));
  return p;
}

//--------------------------------------------------------------------------
// Copy from another hex_place_t object
void ida_export hex_place_t__copyfrom(hp_t *ths, const place_t *from)
{
  hp_t *s = (hp_t *)from;
  ths->d      = s->d;
  ths->n      = s->n;
  ths->lnnum  = s->lnnum;
}

//--------------------------------------------------------------------------
// Create a hex_place_t object at the specified address
// with the specified data
place_t *ida_export hex_place_t__makeplace(const hp_t *ths, void *, uval_t x, short lnnum)
{
  static hex_place_t p;
  p.d     = ths->d;
  p.n     = x;
  p.lnnum = lnnum;
  return &p;
}

//--------------------------------------------------------------------------
// Compare two hex_place_t objects
// Return -1, 0, 1
int ida_export hex_place_t__compare(const hp_t *ths, const place_t *t2)
{
  hp_t *s = (hp_t *)t2;
  return ths->n - s->n;
}

//--------------------------------------------------------------------------
// Check if the location data is correct and if not, adjust it
void ida_export hex_place_t__adjust(hp_t *ths, void *)
{
  if ( ths->n > ths->d->maxline() )
  {
    ths->n = 0;
    ths->lnnum = 0;
  }
}

//--------------------------------------------------------------------------
// Move to the previous location
bool ida_export hex_place_t__prev(hp_t *ths, void *)
{
  if ( ths->n == 0 )
    return false;
  ths->n--;
  return true;
}

//--------------------------------------------------------------------------
// Move to the next location
bool ida_export hex_place_t__next(hp_t *ths, void *)
{
  if ( ths->n >= ths->d->maxline() )
    return false;
  ths->n++;
  return true;
}

//--------------------------------------------------------------------------
// Are we at the beginning of the data?
bool ida_export hex_place_t__beginning(const hp_t *ths, void *)
{
  return ths->n == 0;
}

//--------------------------------------------------------------------------
// Are we at the end of the data?
bool ida_export hex_place_t__ending(const hp_t *ths, void *)
{
  return ths->n == ths->d->maxline();
}

//--------------------------------------------------------------------------
// Generate text for the current location
int ida_export hex_place_t__generate(
        const hp_t *ths,
        void * /*ud*/,
        char *lines[],
        int maxsize,
        int *default_lnnum,
        color_t * /*prefix_color*/,
        bgcolor_t * /*bg_color*/)
{
  int idx = ths->n;
  if ( idx > ths->d->maxline() || maxsize <= 0 )
    return 0;
  uint alignment = ths->d->alignment();
  uchar *data = (uchar *)qalloc(alignment);
  if ( !ths->d->read(alignment * ths->n, data, alignment) )
  {
    qfree(data);
    return 0;
  }

#define HEX_ASCII_SEP   2
  size_t bufsize = 4 * alignment + HEX_ASCII_SEP + 20;
  char *str = (char *)qalloc(bufsize);
  if ( str == NULL )
    nomem("hexplace");
  str[0] = 0;

  // add hex values
  static const char hexstr[] = "0123456789ABCDEF";
  size_t pos = qstrlen(str);
  for ( uint i = 0; i < alignment; i++ )
  {
    str[pos++] = ' ';
    uchar c = data[i];
    str[pos++] = hexstr[c >> 4];
    str[pos++] = hexstr[c & 0xF];
  }

  memset(&str[pos], ' ', HEX_ASCII_SEP);
  pos += HEX_ASCII_SEP;

  // add ascii values
  char *end = tag_on(str + pos, str + bufsize, COLOR_NUMBER);
  pos = (size_t)(end - str);
  for ( uint i = 0; i < alignment; i++ )
    str[pos++] = qisprint(data[i]) ? (char)data[i] : '.';
  end = tag_off(str + pos, str + bufsize, COLOR_NUMBER);
  *end = 0;

  qfree(data);
  lines[0] = str;
  *default_lnnum = 0;
  return 1;
}

