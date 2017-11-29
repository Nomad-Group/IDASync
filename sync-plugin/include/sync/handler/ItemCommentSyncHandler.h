#pragma once
#include "sync/SyncHandlerImpl.h"

struct ItemCommentSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	bool repeatable;
	std::string text;
};

class ItemCommentSyncHandler : public SyncHandlerImpl<ItemCommentSyncUpdateData, SyncType::ItemComment>
{
public:
	ItemCommentSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::cmt_changed)
	{}

protected:
	virtual bool ApplyUpdateImpl(ItemCommentSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, ItemCommentSyncUpdateData*) override;

	virtual void DecodePacketImpl(ItemCommentSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, ItemCommentSyncUpdateData*) override;
};