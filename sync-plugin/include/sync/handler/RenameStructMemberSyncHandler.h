#pragma once
#include "sync/SyncHandlerImpl.h"

struct RenameStructMemberUpdateData : IdbUpdateData
{
	std::string structName;

	uint64_t offset;
	std::string memberName;
};

class RenameStructMemberSyncHandler : public SyncHandlerImpl<RenameStructMemberUpdateData, SyncType::RenameStructMember>
{
public:
	RenameStructMemberSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_member_renamed)
	{}

protected:
	virtual bool ApplyUpdateImpl(RenameStructMemberUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, RenameStructMemberUpdateData*) override;

	virtual void DecodePacketImpl(RenameStructMemberUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, RenameStructMemberUpdateData*) override;
};