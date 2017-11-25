#pragma once
#include "ISyncHandler.h"
#include "network/NetworkBuffer.h"

#include "network/packets/BasePacket.h"

struct IdbUpdate;
class SyncManager
{
	// Sync Handler
	static constexpr const size_t NumSyncHandlers = (size_t)SyncType::_Count;
	ISyncHandler* m_syncHandler[NumSyncHandlers];

public:
	SyncManager() = default;
	~SyncManager();

	// Initialize
	bool Initialize();

	// Sync Handler
	ISyncHandler* GetSyncHandler(SyncType);

	// Packets
	IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*);
	NetworkBufferT<BasePacket>* EncodePacket(IdbUpdate*);

	// Apply Update
	bool ApplyUpdate(IdbUpdate*);
};

extern SyncManager* g_syncManager;