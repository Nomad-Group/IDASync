#pragma once
#include "sync/SyncHandlerImpl.h"

struct UndefineSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
};

class UndefineSyncHandler : public SyncHandlerImpl<UndefineSyncUpdateData, SyncType::Undefine>
{
public:
	UndefineSyncHandler() : SyncHandlerImpl(IdaNotificationType::idp, processor_t::undefine)
	{}

protected:
	virtual bool ApplyUpdateImpl(UndefineSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&,UndefineSyncUpdateData*) override;

	virtual void DecodePacketImpl(UndefineSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*,UndefineSyncUpdateData*) override;
};