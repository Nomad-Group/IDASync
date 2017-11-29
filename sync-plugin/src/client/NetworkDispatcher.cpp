#include "client/NetworkDispatcher.h"
#include "SyncPlugin.h"

void NetworkDispatcher::EnqueueNetworkEvent(NetworkEvent* request)
{
	std::lock_guard<std::mutex> lock(m_eventQueue.lock);
	m_eventQueue.events.push_back(request);

	if(m_eventQueue.events.size() == 1)
		execute_sync(m_eventQueue, MFF_WRITE | MFF_NOWAIT);
}

NetworkDispatcher::NetworkEvent* NetworkDispatcher::NetworkEventQueue::Dequeue()
{
	std::lock_guard<std::mutex> lock(lock);
	if (events.size() == 0)
		return nullptr;

	auto networkEvent = events.front();
	events.erase(events.begin());

	return networkEvent;
}

int idaapi NetworkDispatcher::NetworkEventQueue::execute()
{
	auto networkEvent = Dequeue();
	while (networkEvent != nullptr)
	{
		// Handle Event
		switch (networkEvent->type)
		{
		case NetworkEventType::OnPacket:
		{
			g_plugin->HandleNetworkPacket(networkEvent->data.packet);
			delete networkEvent->data.packet;
		} break;

		case NetworkEventType::OnConnectionClosed:
			g_plugin->HandleDisconnect();
			break;

		default:
			break;
		}

		delete networkEvent;

		// Next
		networkEvent = Dequeue();
	}

	return 0;
}

bool NetworkDispatcher::OnPacket(NetworkBufferT<BasePacket>* packet)
{
	auto networkEvent = new NetworkEvent();
	networkEvent->type = NetworkEventType::OnPacket;
	networkEvent->data.packet = packet;

	EnqueueNetworkEvent(networkEvent);
	return true;
}

void NetworkDispatcher::OnConnectionClosed()
{
	auto networkEvent = new NetworkEvent();
	networkEvent->type = NetworkEventType::OnConnectionClosed;

	EnqueueNetworkEvent(networkEvent);
}