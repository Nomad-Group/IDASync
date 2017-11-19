
// This file is included from 4 places:
//      - efd/pdb.cpp                   efd: to dump pdb contents
//      - base/pdb2til.cpp              tilib: to convert pdb to til
//      - plugins/pdb.cpp               ida: read pdb info and populate idb
//      - dbg/common/tilfuncs.cpp       win32_server: read pdb info and send it to ida
//
// The following symbols may be defined:
// EFD_COMPILE          efd
// PDBTOTIL             tilib
// ENABLE_REMOTEPDB     win32_server or pdb_on_unix
// PDB_PLUGIN           pdb (on any platform)

#include <diskio.hpp>
#include "common.h"

#include "pdbaccess.cpp"
#include "pdblocal.cpp"
#include "pdbreg.cpp"
#include "../../ldr/pe/pe.h"

// We only enable remote PDB fetching in case
// we are building the plugin, for the moment.
// While this is an annoying limitation, it's mostly
// because the pdbremote code requires that
// the 'win32' (stub) debugger be loadable, in order
// to work: Ideally, we should only use an rpc_client
// instance, but currently we channel PDB requests
// through the remote debugger connection.
// (Neither efd.exe, nor tilib.exe can use of a
//  running win32_remote.exe debugger instance for the
//  moment)
#if defined(PDB_PLUGIN) && defined(ENABLE_REMOTEPDB)
#include "pdbremote.cpp"
#endif

#if defined(PDB_PLUGIN) || defined(PDBTOTIL)
#include "tilbuild.cpp"
#endif

#ifdef __NT__

//lint -esym(843, g_diadlls, g_pdb_errors) could be declared as const

int pdb_session_t::session_count = 0;
bool pdb_session_t::co_initialized = false;

//----------------------------------------------------------------------
// Common code for PDB handling
//----------------------------------------------------------------------
class CCallback : public IDiaLoadCallback2,
                  public IDiaReadExeAtRVACallback,
                  public IDiaReadExeAtOffsetCallback
{
  int m_nRefCount;
  ea_t m_load_address;
  HANDLE hFile;
  input_exe_reader_t exe_reader;
  input_mem_reader_t mem_reader;
  void *user_data;
  pdb_session_t *pdb_session;
  debug_entry_t last_de;
public:
  CCallback(input_exe_reader_t _exe_reader,
            input_mem_reader_t _mem_reader,
            void *_user_data,
            pdb_session_t *_pdb_session):
      exe_reader(_exe_reader), mem_reader(_mem_reader),
      m_load_address(BADADDR), m_nRefCount(0), hFile(INVALID_HANDLE_VALUE),
      user_data(_user_data),
      pdb_session(_pdb_session)
  {
    memset(&last_de, 0, sizeof(last_de));
  }

  virtual ~CCallback()
  {
    if ( hFile != INVALID_HANDLE_VALUE )
      CloseHandle(hFile);
  }

  void SetLoadAddress(ea_t load_address)
  {
    m_load_address = load_address;
  }

  void OpenExe(LPCWSTR FileName)
  {
    if ( exe_reader != NULL )
      return;
    hFile = CreateFileW(
      FileName,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);
  }

  // IUnknown
  ULONG STDMETHODCALLTYPE AddRef()
  {
    return ++m_nRefCount;
  }

  ULONG STDMETHODCALLTYPE Release()
  {
    if ( --m_nRefCount == 0 )
    {
      delete this;
      return 0;
    }
    return m_nRefCount;
  }

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID rid, void **ppUnk)
  {
    if ( ppUnk == NULL )
      return E_INVALIDARG;
    if ( rid == __uuidof(IDiaLoadCallback2) || rid == __uuidof(IDiaLoadCallback) )
      *ppUnk = (IDiaLoadCallback2 *)this;
    else if ( rid == __uuidof( IDiaReadExeAtRVACallback ) && m_load_address != BADADDR )
      *ppUnk = (IDiaReadExeAtRVACallback *)this;
    else if ( rid == __uuidof(IDiaReadExeAtOffsetCallback) )
    {
      if ( hFile != INVALID_HANDLE_VALUE || exe_reader != NULL )
      {
        // we have a real file or an EXE reader
        *ppUnk = (IDiaReadExeAtOffsetCallback *)this;
      }
      else
      {
        *ppUnk = NULL;
      }
    }
    else if ( rid == __uuidof(IUnknown) )
        *ppUnk = (IUnknown *)(IDiaLoadCallback *)this;
    else
        *ppUnk = NULL;
    if ( *ppUnk == NULL )
      return E_NOINTERFACE;
    AddRef();
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyDebugDir(
              BOOL fExecutable,
              DWORD cbData,
              BYTE data[])
  {
    // msdia90.dll can crash on bogus data
    // so we remember the offset here and check it in ReadFileAt
    if ( fExecutable && cbData >= sizeof(last_de) )
    {
      memcpy(&last_de, data, sizeof(last_de));
    }
    else
    {
      memset(&last_de, 0, sizeof(last_de));
    }
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE NotifyOpenDBG(
              LPCOLESTR dbgPath,
              HRESULT resultCode)
  {
    qstring spath;
    u2cstr(dbgPath, &spath);
    if ( SUCCEEDED(resultCode) )
      deb(IDA_DEBUG_DEBUGGER, "PDB: found DBG file: '%s'\n", spath.c_str());
    else
      deb(IDA_DEBUG_DEBUGGER, "PDB: '%s': %s\n", spath.c_str(), pdberr(resultCode));
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyOpenPDB(
              LPCOLESTR pdbPath,
              HRESULT resultCode)
  {
    qstring spath;
    u2cstr(pdbPath, &spath);
    if ( SUCCEEDED(resultCode) )
      deb(IDA_DEBUG_DEBUGGER, "PDB: '%s' matched.\n", spath.c_str());
    else
      deb(IDA_DEBUG_DEBUGGER, "PDB: '%s': %s\n", spath.c_str(), pdberr(resultCode));
#ifdef _DEBUG
    pdb_session->pdb_path = spath;
#endif
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictRegistryAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictOriginalPathAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictReferencePathAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictDBGAccess()
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSystemRootAccess()
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE ReadExecutableAtRVA(
   DWORD  relativeVirtualAddress,
   DWORD  cbData,
   DWORD* pcbData,
   BYTE   data[] )
  {
    if ( mem_reader != NULL )
    {
      uint32 read;
      bool ok = mem_reader(m_load_address + relativeVirtualAddress, cbData, data, &read, user_data);
      if ( !ok )
        return E_FAIL;
      *pcbData = read;
      return S_OK;
    }
#ifdef PDB_PLUGIN
    if ( get_many_bytes(m_load_address + relativeVirtualAddress, data, cbData) )
    {
      *pcbData = cbData;
      return S_OK;
    }
#endif
    return S_FALSE;
  }

  // IDiaReadExeAtOffsetCallback
  HRESULT STDMETHODCALLTYPE ReadExecutableAt(
    DWORDLONG fileOffset,
    DWORD cbData,
    DWORD *pcbData,
    BYTE *pbData)
  {
    if ( exe_reader != NULL )
    {
      uint32 read;
      bool ok = exe_reader(fileOffset, cbData, pbData, &read, user_data);
      if ( !ok )
        return E_FAIL;
      *pcbData = read;
      return S_OK;
    }
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)fileOffset;
    bool ok = hFile != INVALID_HANDLE_VALUE
      && SetFilePointerEx(hFile, pos, NULL, FILE_BEGIN) != 0
      && ReadFile(hFile, pbData, cbData, pcbData, NULL) != 0;
    if ( ok )
    {
      // check if we're reading the debug directory entry
      if ( last_de.type == DBG_CV && last_de.seek == fileOffset && cbData > 4 )
      {
        // check that the data has a valid NB or RSDS signature
        ok = (pbData[0] == 'N' && pbData[1] == 'B' && cbData >= sizeof(cv_info_pdb20_t))
          || (memcmp(pbData, "RSDS", 4) == 0 && cbData >= sizeof(rsds_t));
      }
    }
    return ok ? S_OK : E_FAIL;
  }
};

//---------------------------------------------------------------------------
template<class T> void print_generic(T t)
{
  IDiaPropertyStorage *pPropertyStorage;
  HRESULT hr = t->QueryInterface(__uuidof(IDiaPropertyStorage), (void **)&pPropertyStorage);
  if ( hr == S_OK )
  {
    print_property_storage(pPropertyStorage);
    pPropertyStorage->Release();
  }
}

static const char *const g_pdb_errors[] =
{
  "Operation successful (E_PDB_OK)",
  "(E_PDB_USAGE)",
  "Out of memory (E_PDB_OUT_OF_MEMORY)",
  "(E_PDB_FILE_SYSTEM)",
  "Failed to open the file, or the file has an invalid format (E_PDB_NOT_FOUND)",
  "Signature does not match (E_PDB_INVALID_SIG)",
  "Age does not match (E_PDB_INVALID_AGE)",
  "(E_PDB_PRECOMP_REQUIRED)",
  "(E_PDB_OUT_OF_TI)",
  "(E_PDB_NOT_IMPLEMENTED)",
  "(E_PDB_V1_PDB)",
  "Attempted to access a file with an obsolete format (E_PDB_FORMAT)",
  "(E_PDB_LIMIT)",
  "(E_PDB_CORRUPT)",
  "(E_PDB_TI16)",
  "(E_PDB_ACCESS_DENIED)",
  "(E_PDB_ILLEGAL_TYPE_EDIT)",
  "(E_PDB_INVALID_EXECUTABLE)",
  "(E_PDB_DBG_NOT_FOUND)",
  "(E_PDB_NO_DEBUG_INFO)",
  "(E_PDB_INVALID_EXE_TIMESTAMP)",
  "(E_PDB_RESERVED)",
  "(E_PDB_DEBUG_INFO_NOT_IN_PDB)",
  "(E_PDB_SYMSRV_BAD_CACHE_PATH)",
  "(E_PDB_SYMSRV_CACHE_FULL)",
};

//---------------------------------------------------------------------------
inline void pdberr_suggest_vs_runtime(HRESULT hr)
{
  if ( hr == E_NOINTERFACE )
  {
    msg("<< It appears that MS DIA SDK is not installed.\n"
        "Please try installing \"Microsoft Visual C++ 2008 Redistributable Package / x86\" >>\n");
  }
}

//---------------------------------------------------------------------------
const char *pdberr(int code)
{
  switch ( code )
  {                         // tab in first pos is flag for replace warning to msg
    case E_INVALIDARG:      return "Invalid parameter.";
    case E_UNEXPECTED:      return "Data source has already been prepared.";
    default:
      if ( code >= E_PDB_OK && (code - E_PDB_OK) < qnumber(g_pdb_errors) )
        return g_pdb_errors[code - E_PDB_OK];
  }
  return winerr(code);
}

//----------------------------------------------------------------------
class DECLSPEC_UUID("4C41678E-887B-4365-A09E-925D28DB33C2") DiaSource90;
class DECLSPEC_UUID("1fbd5ec4-b8e4-4d94-9efe-7ccaf9132c98") DiaSource80;
class DECLSPEC_UUID("31495af6-0897-4f1e-8dac-1447f10174a1") DiaSource71;
static const GUID *const g_d90 = &__uuidof(DiaSource90);  // msdia90.dll
static const GUID *const g_d80 = &__uuidof(DiaSource80);  // msdia80.dll
static const GUID *const g_d71 = &__uuidof(DiaSource71);  // msdia71.dll
static const GUID *const g_msdiav[] = { g_d90, g_d80, g_d71 };
static const int         g_diaver[] = { 900,   800,   710 };
static const char *g_diadlls[] = { "msdia90.dll", "msdia80.dll", "msdia71.dll"};

//----------------------------------------------------------------------
HRESULT __stdcall CoCreateInstanceNoReg(
  LPCTSTR szDllName,
  IN REFCLSID rclsid,
  IUnknown* pUnkOuter,
  IN REFIID riid,
  OUT LPVOID FAR* ppv,
  OUT HMODULE *phMod)
{
  // http://lallousx86.wordpress.com/2007/01/29/emulating-cocreateinstance/
  HRESULT hr = REGDB_E_CLASSNOTREG;
  HMODULE hDll;
  do
  {
    hDll = LoadLibrary(szDllName);
    if ( hDll == NULL )
      break;

    HRESULT (__stdcall *GetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID FAR* ppv);
    *(FARPROC*)&GetClassObject = GetProcAddress(hDll, "DllGetClassObject");
    if ( GetClassObject == NULL )
      break;

    IClassFactory *pIFactory;
    hr = GetClassObject(rclsid, IID_IClassFactory, (LPVOID *)&pIFactory);
    if ( FAILED(hr) )
      break;

    hr = pIFactory->CreateInstance(pUnkOuter, riid, ppv);
    pIFactory->Release();
  } while (false);

  if ( FAILED(hr) && hDll != NULL )
    FreeLibrary(hDll);
  else
    *phMod = hDll;

  return hr;
}

//----------------------------------------------------------------------
static void get_input_and_sym_path(
        qwstring *winput,
        qwstring *wspath,
        const char *input_file,
        const char *user_spath)
{
  char env_sympath[4096];
  char temp_path[QMAXPATH];
  char spath[sizeof(spath_prefix)+sizeof(temp_path)+sizeof(spath_suffix)];
  // no symbol path passed? let us compute default values
  if ( user_spath == NULL || user_spath[0] == '\0' )
  {
    // no env var?
    if ( GetEnvironmentVariable("_NT_SYMBOL_PATH", env_sympath, sizeof(env_sympath)) == 0
      || GetLastError() == ERROR_ENVVAR_NOT_FOUND )
    {
      if ( !GetTempPath(sizeof(temp_path), temp_path) )
        temp_path[0] = '\0';
      else
        qstrncat(temp_path, "ida", sizeof(temp_path));
      qsnprintf(spath, sizeof(spath), "%s%s%s", spath_prefix, temp_path, spath_suffix);
      user_spath = spath;
    }
    else
    {
      user_spath = env_sympath;
    }
  }
  c2ustr(user_spath, wspath);
  c2ustr(input_file, winput);
}

//----------------------------------------------------------------------------
static DWORD get_machine_type(DWORD dwMachType)
{
  DWORD machine;
  switch ( dwMachType )
  {
    default:
      machine = CV_CFL_80386;
      break;
    case IMAGE_FILE_MACHINE_IA64:
      machine = CV_CFL_IA64;
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      machine = CV_CFL_AMD64;
      break;
    case IMAGE_FILE_MACHINE_THUMB:
    case IMAGE_FILE_MACHINE_ARM:
      machine = CV_CFL_ARM6;
      break;
    case PECPU_ARMV7:
      machine = CV_CFL_ARM7;
      break;
    case PECPU_PPC:
      machine = CV_CFL_PPC620;
      break;
    case PECPU_PPCFP:
      machine = CV_CFL_PPCFP;
      break;
    case PECPU_PPCBE:
      machine = CV_CFL_PPCBE;
      break;
  }
  return machine;
}

//----------------------------------------------------------------------
pdb_session_t::~pdb_session_t()
{
  if ( --session_count == 0 && co_initialized )
  {
    CoUninitialize();
    co_initialized = false;
  }
}

//----------------------------------------------------------------------
void pdb_session_t::close()
{
  if ( pdb_access != NULL )
  {
    delete pdb_access;
    pdb_access = NULL;
  }

  if ( dia_hmod != NULL )
  {
    FreeLibrary(dia_hmod);
    dia_hmod = NULL;
  }

#ifdef _DEBUG
  if ( !pdb_path.empty() )
  {
    HANDLE hFile = CreateFileA(pdb_path.begin(), GENERIC_READ, /*FILE_SHARE_READ*/ 0, 0, OPEN_EXISTING, 0, 0);
    if ( hFile == INVALID_HANDLE_VALUE )
      warning("Couldn't acquire probing lock to %s; file might be still locked by IDA", pdb_path.begin());
    else
      CloseHandle(hFile);
  }
#endif
}

//----------------------------------------------------------------------------
static HRESULT check_and_load_pdb(
        IDiaDataSource *pSource,
        LPCOLESTR pdb_file_pth,
        const pdb_signature_t &pdb_sign,
        bool types_only)
{
  bool load_anyway = types_only;
  HRESULT hr = E_FAIL;
  if ( !load_anyway )
  {
    uint32 sig = pdb_sign.sig;
    uint32 age = pdb_sign.age;
    GUID *pcsig70 = NULL;
    for ( int i=0; i < qnumber(pdb_sign.guid); i++ )
    {
      if ( pdb_sign.guid[i] != 0 )
      {
        pcsig70 = (GUID *)&pdb_sign.guid;
        break;
      }
    }
    if ( sig == 0 && age == 0 && pcsig70 == NULL )
      return E_FAIL;
    hr =  pSource->loadAndValidateDataFromPdb(pdb_file_pth, pcsig70, sig, age);
    if ( hr == E_PDB_INVALID_SIG || hr == E_PDB_INVALID_AGE )
    {
      load_anyway = askyn_c(ASKBTN_NO,
                        "HIDECANCEL\nICON WARNING\nAUTOHIDE NONE\n"
                        "PDB signature and/or age does not match the input file.\n"
                        "Do you want to load it anyway?") == ASKBTN_YES;
    }
  }
  if ( load_anyway )
    hr = pSource->loadDataFromPdb(pdb_file_pth);
  return hr;
}

//----------------------------------------------------------------------------
HRESULT pdb_session_t::open_session(const pdbargs_t &pdbargs)
{
  // Already open?
  if ( pdb_access != NULL )
    return S_OK;

  // Not initialized yet?
  if ( !co_initialized )
  {
    // Initialize COM
    CoInitialize(NULL);
    co_initialized = true;
  }

  // When the debugger is active, first try to load debug directory from the memory
  ea_t load_addrs[2];
  // when remote debugging, don't use files on disk
  bool remote_debug = false;
  ea_t load_address = pdbargs.loaded_base;
#ifdef PDB_PLUGIN
  if ( get_process_state() != DSTATE_NOTASK )
  {
    load_addrs[0] = load_address;
    load_addrs[1] = BADADDR;
    remote_debug = dbg->is_remote();
  }
  else
#endif
  {
    load_addrs[0] = BADADDR;
    load_addrs[1] = load_address;
  }

  int dia_version;
  HRESULT hr;
  IDiaDataSource *pSource  = NULL;
  IDiaSession    *pSession = NULL;
  IDiaSymbol     *pGlobal  = NULL;
  do
  {
    // No interface was created?
    hr = create_dia_source(&pSource, &dia_version);
    if ( FAILED(hr) )
      goto CLEANUP;

    used_fname = pdbargs.pdb_path;
    if ( used_fname.empty() || !qfileexist(used_fname.c_str()) )
    {
      qstring tmp;
      const char *ptr = pdbargs.input_path.c_str();
      if ( *ptr == '\0' )
        ptr = used_fname.c_str();
      if ( !qfileexist(ptr) )
      { // If the input path came from a remote system, it is unlikely to be
        // correct on our system. DIA does not care about the exact file name
        // but uses the directory path to locate the PDB file. It combines
        // the name of the pdb file from the debug directory and the directory
        // from the input path.
        // Since we can not rely on remote paths, we simply use the current dir
        char buf[QMAXPATH];
        qgetcwd(buf, sizeof(buf));
        tmp.sprnt("%s\\%s", buf, qbasename(ptr));
        ptr = tmp.begin();
      }
      if ( !used_fname.empty() )
        msg("%s: not found, trying %s\n", used_fname.begin(), ptr);
      used_fname = ptr;
    }

    qwstring wpath, winput;
    get_input_and_sym_path(&winput, &wpath, used_fname.begin(), pdbargs.spath);

    // Try to load input file as PDB
    bool types_only = (pdbargs.flags & PDBFLG_ONLY_TYPES) != 0;
    hr = check_and_load_pdb(pSource, winput.c_str(), pdbargs.pdb_sign, types_only);
    if ( hr == E_PDB_INVALID_SIG || hr == E_PDB_INVALID_AGE ) // Mismatching PDB
      goto CLEANUP;

    // Failed? Try to load as EXE
    if ( FAILED(hr) )
    {

      CCallback callback(pdbargs.exe_reader, pdbargs.mem_reader, pdbargs.user_data, this);
      callback.AddRef();

      if ( !remote_debug )
      {
        // Open the executable
        callback.OpenExe(winput.c_str());
      }

#ifdef _DEBUG
      // If we are here, and have a ".pdb" file, we're dead.
      // It's not even worth the effort going through the
      // (possibly-remote) reading of the .exe file.
      const char *ext = get_file_ext(used_fname.begin());
      if ( ext != NULL && strieq(ext, "pdb") )
        warning("File \"%s\" appears to be a PDB file."
                " 'loadDataForExe()' is not gonna like it.", used_fname.begin());
#endif
      for ( int i=0; i < qnumber(load_addrs); i++ )
      {
        deb(IDA_DEBUG_DEBUGGER, "PDB: Trying loadDataForExe with %a\n", load_addrs[i]);
        callback.SetLoadAddress(load_addrs[i]);
        hr = pSource->loadDataForExe(winput.c_str(), wpath.c_str(), (IDiaLoadCallback *)&callback);
        deb(IDA_DEBUG_DEBUGGER, "PDB: loadDataForExe: %x\n", hr);
        if ( SUCCEEDED(hr) )
          break;
        // if pdb is not found, is there any sense of trying again with
        // another address?
        if ( hr == E_PDB_NOT_FOUND )
          break;
        if ( load_addrs[0] == load_addrs[1] )
          break; // no need to try again with the same address
      }
    }

    // Failed? Then nothing else to try, quit
    if ( FAILED(hr) )
      goto CLEANUP;

    // Open a session for querying symbols
    hr = pSource->openSession(&pSession);
    if ( FAILED(hr) )
      goto CLEANUP;

    // Set load address
    if ( load_address != BADADDR )
    {
      msg("PDB: using load address %a\n", load_address);
      pSession->put_loadAddress(load_address);
    }

    // Retrieve a reference to the global scope
    hr = pSession->get_globalScope(&pGlobal);
    if ( FAILED(hr) )
      goto CLEANUP;

    hr = S_OK;
  } while ( false );

  // Make sure we cleanup
  if ( FAILED(hr) )
    goto CLEANUP;

  pdb_access = new local_pdb_access_t(pdbargs, pSource, pSession, pGlobal);

  DWORD pdb_machType, machType;
  if ( pGlobal->get_machineType(&pdb_machType) != S_OK )
    pdb_machType = IMAGE_FILE_MACHINE_I386;
  machType = get_machine_type(pdb_machType);

  pdb_access->set_machine_type(machType);
  pdb_access->set_dia_version(dia_version);

  hr = pdb_access->init();
  if ( FAILED(hr) )
    goto CLEANUP;

  return hr;

 CLEANUP:
  // In the event of an error, this will be reached.
  if ( pdb_access == NULL )
  {
    if ( pGlobal != NULL )
      pGlobal->Release();
    if ( pSession != NULL )
      pSession->Release();
    if ( pSource != NULL )
      pSource->Release();
  }
  return hr;
}

//----------------------------------------------------------------------
HRESULT pdb_session_t::create_dia_source(IDiaDataSource **pSource, int *dia_version)
{
  HRESULT hr;
  // VC80/90 CRT installs msdiaNN.dll in this folder:
  // "C:\Program Files (x86)\Common Files\microsoft shared\VC"
  char common_files[QMAXPATH];
  qstring vc_shared;
  if ( get_special_folder(CSIDL_PROGRAM_FILES_COMMON, common_files, sizeof(common_files)) )
  {
    vc_shared = common_files;
    vc_shared.append("\\Microsoft Shared\\VC");
  }

  for ( size_t i=0; i < qnumber(g_msdiav); i++ )
  {
    // Try to create using CoCreateInstance()
    hr = CoCreateInstance(*g_msdiav[i],
                          NULL,
                          CLSCTX_INPROC_SERVER,
                          __uuidof(IDiaDataSource),
                          (void**)pSource);

    // Try to create with CoCreateInstanceNoReg()
    if ( FAILED(hr) )
    {
      // Search for this interface in DIA dlls
      char path[QMAXPATH];
      if ( !search_path(g_diadlls[i], path, sizeof(path), false)
           && (vc_shared.empty() || SearchPathA(vc_shared.c_str(), g_diadlls[i], NULL, qnumber(path), path, NULL) == 0) )
        continue;

      for ( size_t j=0; j < qnumber(g_msdiav); j++ )
      {
        hr = CoCreateInstanceNoReg(path,
                                   *g_msdiav[j],
                                   NULL,
                                   __uuidof(IDiaDataSource),
                                   (void**)pSource,
                                   &dia_hmod);

        if ( SUCCEEDED(hr) )
        {
          static bool displayed = false;
          if ( !displayed )
          {
            displayed = true;
            msg("PDB: using DIA dll \"%s\"\n", path);
          }
          i = j;
          break;
        }
      }
    }

    if ( SUCCEEDED(hr) )
    {
      *dia_version = g_diaver[i];
      static bool displayed = false;
      if ( !displayed )
      {
        displayed = true;
        msg("PDB: DIA interface version %d.%d\n", (*dia_version)/100, (*dia_version)%100);
      }
      return hr;
    }
    else
    {
      *dia_version = 0;
    }
  }
  return E_NOINTERFACE;
}

//----------------------------------------------------------------------
pdb_session_ref_t::pdb_session_ref_t(const pdb_session_ref_t &r)
  : session(r.session)
{
  if ( session != NULL )
    session->refcount++;
}

//----------------------------------------------------------------------
pdb_session_ref_t &pdb_session_ref_t::operator=(const pdb_session_ref_t &r)
{
  if ( &r != this )
  {
    this->~pdb_session_ref_t();
    new (this) pdb_session_ref_t(r);
  }
  return *this;
}

//----------------------------------------------------------------------------
pdb_session_ref_t::~pdb_session_ref_t()
{
  close();
  if ( session != NULL )
  {
    delete session;
    session = NULL;
  }
}

//----------------------------------------------------------------------
void pdb_session_ref_t::create_session(void)
{
  QASSERT(30462, session == NULL);
  session = new pdb_session_t();
}

//----------------------------------------------------------------------
void pdb_session_ref_t::close()
{
  if ( session != NULL )
  {
    // shared instance? then detach
    if ( session->refcount > 1 )
    { // unlink
      session->refcount--;
      session = NULL;
    }
    else
    {
      session->close();
    }
  }
}

// //----------------------------------------------------------------------
// DWORD pdb_session_ref_t::get_machine_type(DWORD dwMachType)
// {
//   DWORD machine;
//   switch ( dwMachType )
//   {
//     default:
//       machine = CV_CFL_80386;
//       break;
//     case IMAGE_FILE_MACHINE_IA64:
//       machine = CV_CFL_IA64;
//       break;
//     case IMAGE_FILE_MACHINE_AMD64:
//       machine = CV_CFL_AMD64;
//       break;
//     case IMAGE_FILE_MACHINE_THUMB:
//     case IMAGE_FILE_MACHINE_ARM:
//       machine = CV_CFL_ARM6;
//       break;
//     case PECPU_ARMV7:
//       machine = CV_CFL_ARM7;
//       break;
//     case PECPU_PPC:
//       machine = CV_CFL_PPC620;
//       break;
//     case PECPU_PPCFP:
//       machine = CV_CFL_PPCFP;
//       break;
//     case PECPU_PPCBE:
//       machine = CV_CFL_PPCBE;
//       break;
//   }
//   return machine;
// }

//----------------------------------------------------------------------
HRESULT pdb_session_ref_t::open_session(const pdbargs_t &pdbargs)
{
  if ( opened() )
    return S_OK;

  if ( empty() )
    create_session();

  return session->open_session(pdbargs);
}

#endif // __NT__
