#pragma once
#include "BaseIdbUpdatePacket.h"

struct IdbNameAddressPacket : BaseIdbUpdatePacket<PacketType::IdbNameAddressPacket>
{
	uint64_t ptr;
	char name[128];
	bool local;
};