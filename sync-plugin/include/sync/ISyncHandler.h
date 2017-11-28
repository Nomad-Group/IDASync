#pragma once
#include "network/NetworkBuffer.h"
#include "network/packets/BasePacket.h"

#include "ida/IdaNotification.h"

enum class SyncType : uint16_t
{
	Name = 0,

	ItemComment,
	ItemType,

	AddFunc,

	_Count
};

struct IdbUpdate;
struct ISyncHandler
{
	virtual ~ISyncHandler() = default;

	// Update
	virtual bool ApplyUpdate(IdbUpdate*) = 0;

	// Ida Notifications
	virtual bool OnIdaNotification(IdaNotification&) = 0;

	// Packet
	virtual IdbUpdate* DecodePacket(NetworkBufferT<BasePacket>*) = 0;
	virtual bool EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdate*) = 0;
}; 