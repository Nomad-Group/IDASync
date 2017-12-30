#pragma once
#include "BasePacket.h"

struct HeartbeatPackage : BasePacketEnumType<PacketType::Heartbeat>
{
	uint32_t timestamp;
};