#pragma once
#include "sync/SyncHandlerImpl.h"

struct ChangeStructMemberUpdateData : IdbUpdateData
{
	std::string structName;

	uint64_t offset;
};

class ChangeStructMemberSyncHandler : public SyncHandlerImpl<ChangeStructMemberUpdateData, SyncType::ChangeStructMember>
{
public:
	ChangeStructMemberSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_member_changed)
	{}

protected:
	virtual bool ApplyUpdateImpl(ChangeStructMemberUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, ChangeStructMemberUpdateData*) override;

	virtual void DecodePacketImpl(ChangeStructMemberUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, ChangeStructMemberUpdateData*) override;
};