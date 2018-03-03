#pragma once
#include "sync/SyncHandlerImpl.h"

struct RenameStructUpdateData : IdbUpdateData
{
	std::string oldName;
	std::string newName;
};

class RenameStructSyncHandler : public SyncHandlerImpl<RenameStructUpdateData, SyncType::RenameStruct>
{
public:
	RenameStructSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_renamed)
	{}

protected:
	virtual bool ApplyUpdateImpl(RenameStructUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, RenameStructUpdateData*) override;

	virtual void DecodePacketImpl(RenameStructUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, RenameStructUpdateData*) override;
};