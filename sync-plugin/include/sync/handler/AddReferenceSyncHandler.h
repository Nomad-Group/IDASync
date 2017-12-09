#pragma once
#include "sync/SyncHandlerImpl.h"

enum class ReferenceType : uint8_t
{
	Code = 0,
	Data = 1
};

struct AddReferenceSyncUpdateData : IdbUpdateData
{
	ReferenceType referenceType;

	uint64_t ptrFrom;
	uint64_t ptrTo;
	uint32_t referenceDataType; // cref_t / dref_t
};

class AddReferenceSyncHandler : public SyncHandlerImpl<AddReferenceSyncUpdateData, SyncType::AddReference>
{
protected:
	virtual bool ApplyUpdateImpl(AddReferenceSyncUpdateData*) override;

	virtual bool ShouldHandleNotification(IdaNotification&) override;
	virtual bool HandleNotification(IdaNotification&, AddReferenceSyncUpdateData*) override;

	virtual void DecodePacketImpl(AddReferenceSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, AddReferenceSyncUpdateData*) override;
};