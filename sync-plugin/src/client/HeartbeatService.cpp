#include "client/HeartbeatService.h"
#include "network/NetworkClient.h"
#include "SyncPlugin.h"

void HeartbeatService::Reset()
{
	m_lastHeartbeat = std::chrono::system_clock::now();
	m_uiNumHeartbeats = 0;
}

bool HeartbeatService::HandleHeartbeat(NetworkBufferT<HeartbeatPackage>* pHeartbeat)
{
	m_lastHeartbeat = std::chrono::system_clock::now();
	m_uiNumHeartbeats++;

	// Reply
	g_client->Send(pHeartbeat);
	delete pHeartbeat;

	// Done
	return true;
}

void HeartbeatService::Update()
{
	m_uiNumHeartbeats++;
	if (m_uiNumHeartbeats <= 10)
		return;

	if ((std::chrono::system_clock::now() - m_lastHeartbeat) > std::chrono::milliseconds(5100))
	{
		g_plugin->Log("Disconnecting now, Sever has not sent us a Heartbeat in some time...");
		g_client->Disconnect();
	}
}