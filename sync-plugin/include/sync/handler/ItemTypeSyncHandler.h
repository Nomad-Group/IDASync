#pragma once
#include "sync/ISyncHandler.h"
#include "sync/IdbUpdate.h"

#include <typeinf.hpp>
#include <string>

struct ItemTypeSyncUpdateData : IdbUpdate
{
	uint64_t ptr;
	std::string type; // const type_t*
	std::string fnames; // const p_list*
};

class ItemTypeSyncHandler : public ISyncHandler
{
public:
	virtual bool ApplyUpdate(IdbUpdate*) override;

	virtual bool OnIdaNotification(IdaNotification&) override;

	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) override;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) override;
};