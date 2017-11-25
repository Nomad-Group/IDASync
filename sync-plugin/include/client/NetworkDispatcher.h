#pragma once
#include "network/NetworkClient.h"
#include "idp.hpp"

class NetworkDispatcher : public INetworkClientEventListener
{
private:
	struct OnPacketEvent : exec_request_t
	{
		NetworkBufferT<BasePacket>* m_packet;
		virtual int idaapi execute() override;
	};
	struct OnConnectionClosedEvent : exec_request_t
	{
		virtual int idaapi execute() override;
	};
	
	void QueueEvent(exec_request_t*);

public:
	virtual bool OnPacket(NetworkBufferT<BasePacket>*) override;
	virtual void OnConnectionClosed() override;
};