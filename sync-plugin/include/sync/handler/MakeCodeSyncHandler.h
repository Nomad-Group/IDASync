#pragma once
#include "sync/SyncHandlerImpl.h"

struct MakeCodeSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	//uint64_t len;
};

class MakeCodeSyncHandler : public SyncHandlerImpl<MakeCodeSyncUpdateData, SyncType::MakeCode>
{
public:
	MakeCodeSyncHandler() : SyncHandlerImpl(IdaNotificationType::idp, processor_t::make_code)
	{}

protected:
	virtual bool ApplyUpdateImpl(MakeCodeSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, MakeCodeSyncUpdateData*) override;

	virtual void DecodePacketImpl(MakeCodeSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, MakeCodeSyncUpdateData*) override;
};