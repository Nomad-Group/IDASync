#pragma once
#include "sync/SyncHandlerImpl.h"

#include <typeinf.hpp>

struct ItemTypeSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	std::string type; // const type_t*
	std::string fnames; // const p_list*
};

class ItemTypeSyncHandler : public SyncHandlerImpl<ItemTypeSyncUpdateData, SyncType::ItemType>
{
public:
	ItemTypeSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::ti_changed)
	{}

protected:
	virtual bool ApplyUpdateImpl(ItemTypeSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, ItemTypeSyncUpdateData*) override;

	virtual void DecodePacketImpl(ItemTypeSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, ItemTypeSyncUpdateData*) override;
};