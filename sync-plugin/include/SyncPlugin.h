#pragma once
#include <string>

class SyncPlugin
{
private:
	bool InstallIDBHook();

public:
	bool Init();
	void Shutdown();

	void Run();

	// Logging
	
	void Log(const std::string& message);
	void ShowInfoDialog(const std::string& message);
	void ShowErrorDialog(const std::string& message);
};

extern SyncPlugin* g_plugin;