#include "client/NetworkDispatcher.h"
#include "SyncPlugin.h"

void NetworkDispatcher::QueueEvent(exec_request_t* request)
{
	execute_sync(*request, MFF_WRITE | MFF_NOWAIT);
}

bool NetworkDispatcher::OnPacket(NetworkBufferT<BasePacket>* packet)
{
	auto dispatchEvent = new OnPacketEvent();
	dispatchEvent->m_packet = packet;

	QueueEvent(dispatchEvent);
	return true;
}
int idaapi NetworkDispatcher::OnPacketEvent::execute()
{
	// Handle Packet
	g_plugin->HandleNetworkPacket(m_packet);

	// Cleanup
	delete m_packet;
	delete this;

	return 0;
}

void NetworkDispatcher::OnConnectionClosed()
{
	auto dispatchEvent = new OnConnectionClosedEvent();

	QueueEvent(dispatchEvent);
}
int idaapi NetworkDispatcher::OnConnectionClosedEvent::execute()
{
	g_plugin->HandleDisconnect();

	// Cleanup
	delete this;

	return 0;
}