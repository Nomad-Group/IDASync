#pragma once
#include "ISyncHandler.h"
#include "network/NetworkBuffer.h"

#include "network/packets/BasePacket.h"

struct IdbUpdateData;
class SyncManager
{
	// Sync Handler
	static constexpr const size_t NumSyncHandlers = (size_t)SyncType::_Count;
	ISyncHandler* m_syncHandler[NumSyncHandlers];

	// Notifications
	static int __stdcall ida_notification_point(void*, int notificationCode, va_list args);
	bool m_notificationLock = false;

	void OnIdaNotification(IdaNotification&);

public:
	SyncManager() = default;
	~SyncManager();

	// Initialize
	bool Initialize();

	// Sync Handler
	ISyncHandler* GetSyncHandler(SyncType);

	// Apply Update
	bool ApplyUpdate(IdbUpdateData*);
	bool SendUpdate(IdbUpdateData*);

	// Packets
	IdbUpdateData* DecodePacket(NetworkBufferT<BasePacket>*);
	NetworkBufferT<BasePacket>* EncodePacket(IdbUpdateData*);
};

extern SyncManager* g_syncManager;