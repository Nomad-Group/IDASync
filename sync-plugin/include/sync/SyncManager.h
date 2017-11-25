#pragma once
#include "ISyncHandler.h"
#include "network/NetworkBuffer.h"

#include "network/packets/BasePacket.h"

struct IdbUpdate;
class SyncManager
{
	static constexpr const size_t NumSyncHandlers = (size_t)SyncType::_Count;
	ISyncHandler* m_syncHandler[NumSyncHandlers];

public:
	SyncManager() = default;
	~SyncManager();

	bool Initialize();

	IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*);
	NetworkBufferT<BasePacket>* EncodePacket(IdbUpdate*);

	bool ApplyUpdate(IdbUpdate*);
};

extern SyncManager* g_syncManager;