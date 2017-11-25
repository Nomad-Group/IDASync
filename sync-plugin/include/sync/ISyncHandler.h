#pragma once
#include "network/NetworkBuffer.h"
#include "network/packets/BasePacket.h"

enum class SyncType : uint16_t
{
	Name = 0,

	_Count
};

struct IdbUpdate;
struct ISyncHandler
{
	virtual ~ISyncHandler() = default;

	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) = 0;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) = 0;

	virtual bool ApplyUpdate(IdbUpdate*) = 0;
}; 