#pragma once
#include "network/NetworkClient.h"
#include "idp.hpp"

#include <mutex>
#include <vector>

class NetworkDispatcher : public INetworkClientEventListener
{
private:
	enum class NetworkEventType
	{
		OnPacket,
		OnConnectionClosed
	};

	struct NetworkEvent
	{
		NetworkEventType type;

		union
		{
			NetworkBufferT<BasePacket>* packet;
		} data;
	};

	struct NetworkEventQueue : exec_request_t
	{
		std::mutex lock;
		std::vector<NetworkEvent*> events;

		NetworkEvent* Dequeue();
		virtual int idaapi execute() override;
	} m_eventQueue;

	void EnqueueNetworkEvent(NetworkEvent*);

public:
	virtual bool OnPacket(NetworkBufferT<BasePacket>*) override;
	virtual void OnConnectionClosed() override;
};