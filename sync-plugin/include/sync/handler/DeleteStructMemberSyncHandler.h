#pragma once
#include "sync/SyncHandlerImpl.h"

struct DeleteStructMemberUpdateData : IdbUpdateData
{
	std::string structName;
	uint64_t offset;
};

class DeleteStructMemberSyncHandler : public SyncHandlerImpl<DeleteStructMemberUpdateData, SyncType::DeleteStructMember>
{
public:
	DeleteStructMemberSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_member_deleted)
	{}

protected:
	virtual bool ApplyUpdateImpl(DeleteStructMemberUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, DeleteStructMemberUpdateData*) override;

	virtual void DecodePacketImpl(DeleteStructMemberUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, DeleteStructMemberUpdateData*) override;
};