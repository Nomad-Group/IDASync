#pragma once
#include "sync/SyncHandlerImpl.h"
#include "AddReferenceSyncHandler.h"

struct DeleteReferenceSyncUpdateData : IdbUpdateData
{
	ReferenceType referenceType;

	uint64_t ptrFrom;
	uint64_t ptrTo;
	bool expand;
};

class DeleteReferenceSyncHandler : public SyncHandlerImpl<DeleteReferenceSyncUpdateData, SyncType::DeleteReference>
{
protected:
	virtual bool ApplyUpdateImpl(DeleteReferenceSyncUpdateData*) override;

	virtual bool ShouldHandleNotification(IdaNotification&) override;
	virtual bool HandleNotification(IdaNotification&, DeleteReferenceSyncUpdateData*) override;

	virtual void DecodePacketImpl(DeleteReferenceSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, DeleteReferenceSyncUpdateData*) override;
};