#pragma once
#include "network/packets/HeartbeatPackage.h"
#include "network/NetworkBuffer.h"

#include <stdint.h>
#include <chrono>

class HeartbeatService
{
	std::chrono::system_clock::time_point m_lastHeartbeat;
	uint32_t m_uiNumHeartbeats = 0;

public:
	void Reset();

	bool HandleHeartbeat(NetworkBufferT<HeartbeatPackage>*);
	void Update();
};