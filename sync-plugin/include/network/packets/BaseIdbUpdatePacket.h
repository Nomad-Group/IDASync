#pragma once
#include "BasePacket.h"

template <PacketType TPacketType>
struct BaseIdbUpdatePacket : BasePacketEnumType<TPacketType>
{
	uint32_t binaryVersion;
};