#include "SyncPlugin.h"
#include "SyncClient.h"
#include <ida.hpp>
#include <idp.hpp>

SyncPlugin* g_plugin = nullptr;

bool SyncPlugin::Init()
{
	bool isX86 = strncmp(inf.procName, "metapc", 8) != 0;

	// IDB Hook
	if (!InstallIDBHook())
	{
		Log("Error: Failed to install IDB Hook!");
		return false;
	}

	return true;
}

void SyncPlugin::Shutdown()
{

}

void SyncPlugin::Run()
{
	g_client = new SyncClient();
	if (g_client->Connect("127.0.0.1"))
		Log("yey!");
}

void SyncPlugin::Log(const std::string& message)
{
	msg("[SyncPlugin] %s\n", message.c_str());
}
void SyncPlugin::ShowErrorDialog(const std::string& message)
{
	error("[SyncPlugin] %s\n", message.c_str());
}
void SyncPlugin::ShowInfoDialog(const std::string& message)
{
	info("[SyncPlugin] %s\n", message.c_str());
}