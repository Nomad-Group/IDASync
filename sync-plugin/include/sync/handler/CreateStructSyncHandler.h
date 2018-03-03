#pragma once
#include "sync/SyncHandlerImpl.h"

struct CreateStructUpdateData : IdbUpdateData
{
	std::string name;
	bool isUnion;
};

class CreateStructSyncHandler : public SyncHandlerImpl<CreateStructUpdateData, SyncType::CreateStruct>
{
public:
	CreateStructSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_created)
	{}

protected:
	virtual bool ApplyUpdateImpl(CreateStructUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, CreateStructUpdateData*) override;

	virtual void DecodePacketImpl(CreateStructUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, CreateStructUpdateData*) override;
};