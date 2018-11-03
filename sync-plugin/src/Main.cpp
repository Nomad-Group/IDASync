#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include "SyncPlugin.h"

int idaapi IDAP_init(void)
{
	g_plugin = new SyncPlugin();
	return g_plugin->Init() ? PLUGIN_KEEP : PLUGIN_SKIP;
}
void idaapi IDAP_term(void)
{
	if (g_plugin)
	{
		g_plugin->Shutdown();
		
		delete g_plugin;
		g_plugin = nullptr;
	}
}
bool idaapi IDAP_run(size_t arg)
{
	if (g_plugin)
		g_plugin->Run();

	return true;
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