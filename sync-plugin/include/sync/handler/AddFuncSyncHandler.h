#pragma once
#include "sync/SyncHandlerImpl.h"

struct AddFuncSyncUpdateData : IdbUpdateData
{
	uint64_t ptrStart;
	uint64_t ptrEnd;
};

class AddFuncSyncHandler : public SyncHandlerImpl<AddFuncSyncUpdateData, SyncType::AddFunc>
{
public:
	AddFuncSyncHandler() : SyncHandlerImpl(IdaNotificationType::idp, processor_t::add_func)
	{}

protected:
	virtual bool ApplyUpdateImpl(AddFuncSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, AddFuncSyncUpdateData*) override;

	virtual void DecodePacketImpl(AddFuncSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, AddFuncSyncUpdateData*) override;
};