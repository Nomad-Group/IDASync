#pragma once
#include "sync/SyncHandlerImpl.h"

struct DeleteStructUpdateData : IdbUpdateData
{
	std::string name;
};

class DeleteStructSyncHandler : public SyncHandlerImpl<DeleteStructUpdateData, SyncType::DeleteStruct>
{
public:
	DeleteStructSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_deleted)
	{}

protected:
	virtual bool ApplyUpdateImpl(DeleteStructUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, DeleteStructUpdateData*) override;

	virtual void DecodePacketImpl(DeleteStructUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, DeleteStructUpdateData*) override;
};