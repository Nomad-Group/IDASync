#pragma once
#include "BasePacket.h"

struct UpdateOperationStartPacket : BasePacketEnumType<PacketType::UpdateOperationStart>
{
	uint32_t numTotalUpdates;
};

struct UpdateOperationProgressPacket : BasePacketEnumType<PacketType::UpdateOperationProgress>
{
	uint32_t numUpdatesSynced;
};

struct UpdateOperationStopPacket : BasePacketEnumType<PacketType::UpdateOperationStop>
{
	uint32_t version;
};