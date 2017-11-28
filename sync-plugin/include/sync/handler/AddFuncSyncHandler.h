#pragma once
#include "sync/ISyncHandler.h"
#include "sync/IdbUpdate.h"

#include <string>

struct AddFuncSyncUpdateData : IdbUpdate
{
	uint64_t ptrStart;
	uint64_t ptrEnd;
};

class AddFuncSyncHandler : public ISyncHandler
{
public:
	virtual bool ApplyUpdate(IdbUpdate*) override;

	virtual bool OnIdaNotification(IdaNotification&) override;

	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) override;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) override;
};