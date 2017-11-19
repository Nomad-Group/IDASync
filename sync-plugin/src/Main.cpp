#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

int __stdcall IDAP_init(void)
{
	msg("[SyncPlugin ] Loading...");
	return PLUGIN_KEEP;
}
void __stdcall IDAP_term(void)
{
	msg("[SyncPlugin ] Terminating...");
	return;
}
void __stdcall IDAP_run(int arg)
{
	msg("[SyncPlugin ] Hello!");
	return;
}

char IDAP_comment[] = "Sync Plugin (Alpha)";
char IDAP_name[] = "Sync Plugin";
char IDAP_hotkey[] = "Alt-L";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0, // Flags
	IDAP_init,
	IDAP_term,
	IDAP_run,
	IDAP_comment,
	IDAP_comment,
	IDAP_name,
	IDAP_hotkey
};