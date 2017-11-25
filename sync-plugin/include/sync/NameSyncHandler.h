#pragma once
#include "ISyncHandler.h"
#include "IdbUpdate.h"

#include <string>

struct NameSyncUpdateData : IdbUpdate
{
	uint64_t ptr;
	std::string name;
};

class NameSyncHandler : public ISyncHandler
{
public:
	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) override;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) override;

	virtual bool ApplyUpdate(IdbUpdate*) override;
};