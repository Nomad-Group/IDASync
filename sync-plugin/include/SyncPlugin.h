#pragma once
#include "network/packets/BasePacket.h"
#include "client/NetworkDispatcher.h"
#include "client/HeartbeatService.h"
#include "client/UpdateOperation.h"
#include <string>

class SyncPlugin
{
	friend class UpdateOperation;

private:
	// Components
	NetworkDispatcher m_dispatcher;
	HeartbeatService m_heartbeatService;
	UpdateOperation m_updateOperation;

	// Packet Handler
	bool HandleBroadcastMessagePacket(NetworkBufferT<BasePacket>*);
	bool HandleIdbUpdatePacket(NetworkBufferT<BasePacket>*);
	bool HandleIdbUpdateResponsePacket(NetworkBufferT<BasePacket>*);

public:
	static const uint32_t VERSION_NUMBER = 4;

	// IDA Callbacks
	bool Init();
	void Shutdown();
	void Run();

	//
	bool Connect();

	// Network Events
	bool HandleNetworkPacket(NetworkBufferT<BasePacket>*);
	void HandleConnectionClosed();
	void HandleDisconnect();

	HeartbeatService* GetHeartbeatService() { return &m_heartbeatService; };
	UpdateOperation* GetUpdateOperation() { return &m_updateOperation; };

	// Logging
	void Log(const std::string& message);
	void ShowInfoDialog(const std::string& message);
	void ShowErrorDialog(const std::string& message);
};

extern SyncPlugin* g_plugin;