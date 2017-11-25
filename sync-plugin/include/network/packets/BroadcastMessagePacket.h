#pragma once
#include "BasePacket.h"

enum class BroadcastMessageType : uint8_t
{
	ClientFirstJoin = 0,
	ClientJoin,
	ClientDisconnect
};

struct BroadcastMessagePacket : BasePacketEnumType<PacketType::BroadcastMessage>
{
	BroadcastMessageType messageType;
};