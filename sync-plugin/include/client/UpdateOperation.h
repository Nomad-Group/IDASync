#pragma once
#include "network/packets/UpdateOperationPackets.h"
#include "network/NetworkBuffer.h"

class UpdateOperation
{
	bool m_bIsActive = false;
	uint32_t m_uiTotalUpdates = 0;

	bool OnStart(NetworkBufferT<UpdateOperationStartPacket>*);
	bool OnProgress(NetworkBufferT<UpdateOperationProgressPacket>*);
	bool OnUpdateBurst(NetworkBufferT<BasePacket>*);
	bool OnEnd(NetworkBufferT<UpdateOperationStopPacket>*);

public:

	bool HandlePacket(NetworkBufferT<BasePacket>*);

	inline bool IsActive() const { return m_bIsActive; };
	void Reset();
};