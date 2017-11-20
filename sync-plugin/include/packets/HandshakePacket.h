#pragma once
#include "BasePacket.h"

struct HandshakePacket : BasePacket
{
	char guid[38];
};