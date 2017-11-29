#pragma once
#include "sync/SyncHandlerImpl.h"

struct NameSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	std::string name;
	bool local;
};

class NameSyncHandler : public SyncHandlerImpl<NameSyncUpdateData, SyncType::Name>
{
public:
	NameSyncHandler() : SyncHandlerImpl(IdaNotificationType::idp, processor_t::renamed)
	{}

protected:
	virtual bool ApplyUpdateImpl(NameSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, NameSyncUpdateData*) override;

	virtual void DecodePacketImpl(NameSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, NameSyncUpdateData*) override;
};