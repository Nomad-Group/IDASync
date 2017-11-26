#pragma once
#include "sync/ISyncHandler.h"
#include "sync/IdbUpdate.h"

#include <string>

struct ItemCommentSyncUpdateData : IdbUpdate
{
	uint64_t ptr;
	bool repeatable;
	std::string text;
};

class ItemCommentSyncHandler : public ISyncHandler
{
public:
	virtual bool ApplyUpdate(IdbUpdate*) override;

	virtual bool OnIdaNotification(IdaNotification&) override;

	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) override;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) override;
};