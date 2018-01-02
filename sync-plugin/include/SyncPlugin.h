#pragma once
#include "network/packets/BasePacket.h"
#include "client/NetworkDispatcher.h"
#include "client/HeartbeatService.h"
#include <string>

class SyncPlugin
{
private:
	// Network
	NetworkDispatcher m_dispatcher;
	HeartbeatService m_heartbeatService;

	// Packet Handler
	bool HandleBroadcastMessagePacket(NetworkBufferT<BasePacket>*);
	bool HandleIdbUpdatePacket(NetworkBufferT<BasePacket>*);
	bool HandleIdbUpdateResponsePacket(NetworkBufferT<BasePacket>*);

	// Update Operation
	uint32_t m_uiUpdateOperationTotalUpdates = 0;
	bool HandleUpdateOperationPacket(NetworkBufferT<BasePacket>*);

public:
	static const uint32_t VERSION_NUMBER = 2;

	// IDA Callbacks
	bool Init();
	void Shutdown();
	void Run();

	// Network Events
	bool HandleNetworkPacket(NetworkBufferT<BasePacket>*);
	void HandleConnectionClosed();
	void HandleDisconnect();

	HeartbeatService* GetHeartbeatService() { return &m_heartbeatService; };
	bool IsUpdateOperationActive() const { return m_uiUpdateOperationTotalUpdates > 0; };

	// Logging
	void Log(const std::string& message);
	void ShowInfoDialog(const std::string& message);
	void ShowErrorDialog(const std::string& message);
};

extern SyncPlugin* g_plugin;