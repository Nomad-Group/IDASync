#pragma once
#include "sync/SyncHandlerImpl.h"

enum class StructMemberType : uint8_t
{
	Data,
	Struct,
	String,
	Enum,
	Offset
};

struct StructMemberUpdateData : IdbUpdateData
{
	std::string structName;
	std::string memberName;
	StructMemberType memberType;

	uint64_t offset;
	uint64_t size;
	uint32_t flag;

	std::string targetStructName;
	int32_t stringType;
	refinfo_t offsetRefInfo;
};

class StructMemberSyncHandler : public SyncHandlerImpl<StructMemberUpdateData, SyncType::CreateStructMember>
{
public:
	StructMemberSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::struc_member_created)
	{}

	virtual bool ShouldHandleNotification(IdaNotification& notification)
	{
		return
			 notification.type == IdaNotificationType::idb &&
			(notification.code == idb_event::struc_member_created || notification.code == idb_event::struc_member_changed);
	}

protected:
	virtual bool ApplyUpdateImpl(StructMemberUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, StructMemberUpdateData*) override;

	virtual void DecodePacketImpl(StructMemberUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, StructMemberUpdateData*) override;
};