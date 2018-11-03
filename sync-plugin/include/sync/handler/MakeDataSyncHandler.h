#pragma once
#include "sync/SyncHandlerImpl.h"

struct MakeDataSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	uint64_t len;

	uint32_t flags;
};

class MakeDataSyncHandler : public SyncHandlerImpl<MakeDataSyncUpdateData, SyncType::MakeData>
{
public:
	MakeDataSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::make_data)
	{}

protected:
	virtual bool ApplyUpdateImpl(MakeDataSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, MakeDataSyncUpdateData*) override;

	virtual void DecodePacketImpl(MakeDataSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, MakeDataSyncUpdateData*) override;
}; 