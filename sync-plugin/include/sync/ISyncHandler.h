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
	Undefine,

	OperandType,
	MakeCode,

	AddReference,
	DeleteReference,

	_Count
};

struct IdbUpdateData;
struct ISyncHandler
{
	virtual ~ISyncHandler() = default;

	// Update
	virtual bool ApplyUpdate(IdbUpdateData*) = 0;

	// Ida Notifications
	virtual bool OnIdaNotification(IdaNotification&) = 0;

	// Packet
	virtual IdbUpdateData* DecodePacket(NetworkBufferT<BasePacket>*) = 0;
	virtual void EncodePacket(NetworkBufferT<BasePacket>*, IdbUpdateData*) = 0;
}; 