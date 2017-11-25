#pragma once
#include "network/packets/BasePacket.h"
#include "client/NetworkDispatcher.h"
#include <string>

class SyncPlugin
{
private:
	// Network
	NetworkDispatcher m_dispatcher;

	// IDA
	bool InstallIDBHook();

	// Packet Handler
	bool HandleBroadcastMessagePacket(NetworkBufferT<BroadcastMessagePacket>*);
	bool HandleIdbUpdatePacket(NetworkBufferT<BasePacket>*);

public:
	// IDA Callbacks
	bool Init();
	void Shutdown();
	void Run();

	// Network Events
	bool HandleNetworkPacket(NetworkBufferT<BasePacket>*);
	void HandleDisconnect();

	// Logging
	void Log(const std::string& message);
	void ShowInfoDialog(const std::string& message);
	void ShowErrorDialog(const std::string& message);
};

extern SyncPlugin* g_plugin;