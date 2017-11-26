#pragma once
#include "sync/ISyncHandler.h"
#include "sync/IdbUpdate.h"

#include <string>

struct NameSyncUpdateData : IdbUpdate
{
	uint64_t ptr;
	std::string name;
};

class NameSyncHandler : public ISyncHandler
{
public:
	virtual bool ApplyUpdate(IdbUpdate*) override;

	virtual bool OnIdaNotification(IdaNotification&) override;

	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) override;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) override;
};