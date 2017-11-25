#pragma once
#include "BasePacket.h"

#pragma pack(push)
struct BaseIdbUpdatePacket : BasePacketEnumType<PacketType::IdbUpdate>
{
	uint32_t binaryVersion;
	uint16_t syncType;
};
#pragma pack(pop)

//static_assert(sizeof(BaseIdbUpdatePacket) == (sizeof(BasePacket) + 6), "BaseIdbUpdatePacket size mismatch");