#include "sync/SyncManager.h"
#include "sync/IdbUpdate.h"
#include "network/NetworkClient.h"
#include "ida/IdbManager.h"

#include "sync/handler/NameSyncHandler.h"

#include "loader.hpp"

SyncManager* g_syncManager = nullptr;

SyncManager::~SyncManager()
{
	for (int i = 0; i < NumSyncHandlers; i++)
		delete m_syncHandler[i];
}

int idaapi SyncManager::ida_notification_point(void* ud, int notificationCode, va_list args)
{
	IdaNotification notification;

	notification.type = (IdaNotificationType) ((uintptr_t)(ud));
	notification.code = notificationCode;
	notification.args = args;

	g_syncManager->OnIdaNotification(notification);
	return 0;
}

bool SyncManager::Initialize()
{
	// Handler
	m_syncHandler[(size_t) SyncType::Name] = new NameSyncHandler();

	// Notification Point
	if (!hook_to_notification_point(hook_type_t::HT_IDB, ida_notification_point, (void*)IdaNotificationType::idb) ||
		!hook_to_notification_point(hook_type_t::HT_IDP, ida_notification_point, (void*)IdaNotificationType::idp))
		return false;

	// Done
	return true;
}

ISyncHandler* SyncManager::GetSyncHandler(SyncType syncType)
{
	if (syncType >= SyncType::_Count)
		return nullptr;

	return m_syncHandler[(size_t) syncType];
}

bool SyncManager::ApplyUpdate(IdbUpdate* updateData)
{
	// Sync Handler
	auto syncHandler = GetSyncHandler(updateData->syncType);
	if (syncHandler == nullptr)
		return false;

	// Apply
	m_notificationLock = true;
	bool success = syncHandler->ApplyUpdate(updateData);
	m_notificationLock = false;

	// Update Version
	if (success)
		g_idb->SetVersion(updateData->version);

	return success;
}

bool SyncManager::SendUpdate(IdbUpdate* updateData)
{
	// Packet
	auto packet = EncodePacket(updateData);
	if (packet == nullptr)
		return false;

	// Send
	return g_client->Send(packet);
}

void SyncManager::OnIdaNotification(IdaNotification& notification)
{
	if (g_client == nullptr || m_notificationLock)
		return;

	for (int i = 0; i < NumSyncHandlers; i++)
	{
		auto syncHandler = m_syncHandler[i];
		if (syncHandler->OnIdaNotification(notification))
			break;
	}
}

IdbUpdate* SyncManager::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	IdbUpdate updateDataHeader;

	// Generic Data
	if (packet == nullptr ||
		!packet->Read(&updateDataHeader.version) ||
		!packet->Read(&updateDataHeader.syncType))
		return nullptr;

	// Sync Handler
	auto syncHandler = GetSyncHandler(updateDataHeader.syncType);
	if (syncHandler == nullptr)
		return nullptr;
	
	// Decode
	auto updateData = syncHandler->DecodePacket(packet);
	if (updateData)
	{
		updateData->version = updateDataHeader.version;
		updateData->syncType = updateDataHeader.syncType;
	}

	// Done
	return updateData;
}

NetworkBufferT<BasePacket>* SyncManager::EncodePacket(IdbUpdate* updateData)
{
	if (updateData == nullptr)
		return nullptr;

	// Packet
	auto packet = new NetworkBufferT<BasePacket>();
	packet->t->packetType = PacketType::IdbUpdate;

	packet->Write(updateData->version);
	packet->Write(updateData->syncType);

	// Sync Handler
	auto syncHandler = GetSyncHandler(updateData->syncType);
	if (syncHandler == nullptr)
		return nullptr;

	// Encode
	if (!syncHandler->EncodePacket(packet, updateData))
	{
		delete packet;
		return nullptr;
	}

	// Done
	return packet;
}