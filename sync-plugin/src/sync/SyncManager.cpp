#include "sync/SyncManager.h"
#include "sync/IdbUpdateData.h"
#include "network/NetworkClient.h"
#include "ida/IdbManager.h"
#include "SyncPlugin.h"

#include "sync/handler/NameSyncHandler.h"
#include "sync/handler/ItemCommentSyncHandler.h"
#include "sync/handler/ItemTypeSyncHandler.h"
#include "sync/handler/AddFuncSyncHandler.h"
#include "sync/handler/UndefineSyncHandler.h"
#include "sync/handler/OperandTypeSyncHandler.h"
#include "sync/handler/MakeCodeSyncHandler.h"
#include "sync/handler/AddReferenceSyncHandler.h"
#include "sync/handler/DeleteReferenceSyncHandler.h"
#include "sync/handler/MakeDataSyncHandler.h"

#include "ida/idb_events_strings.h"
#include "ida/idp_events_strings.h"

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
	m_syncHandler[(size_t) SyncType::ItemComment] = new ItemCommentSyncHandler();
	m_syncHandler[(size_t) SyncType::ItemType] = new ItemTypeSyncHandler();
	m_syncHandler[(size_t) SyncType::AddFunc] = new AddFuncSyncHandler();
	m_syncHandler[(size_t) SyncType::Undefine] = new UndefineSyncHandler();
	m_syncHandler[(size_t) SyncType::OperandType] = new OperandTypeSyncHandler();
	m_syncHandler[(size_t) SyncType::MakeCode] = new MakeCodeSyncHandler();
	m_syncHandler[(size_t) SyncType::AddReference] = new AddReferenceSyncHandler();
	m_syncHandler[(size_t) SyncType::DeleteReference] = new DeleteReferenceSyncHandler();
	m_syncHandler[(size_t) SyncType::MakeData] = new MakeDataSyncHandler();

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

bool SyncManager::ApplyUpdate(IdbUpdateData* updateData)
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

bool SyncManager::SendUpdate(IdbUpdateData* updateData)
{
	// Packet
	auto packet = EncodePacket(updateData);
	if (packet == nullptr)
		return false;

	// Send
	return g_client->Send(packet);
}

void _unhandled_notification(const char* type)
{
	g_plugin->Log("WARNING: You just triggered an event that collabreate would sync! THIS PLUGIN DOES NOT!");
	g_plugin->Log("Event: " + std::string(type));
}

void SyncManager::OnIdaNotification(IdaNotification& notification)
{
	if (g_client == nullptr || !g_client->IsConnected() || m_notificationLock)
		return;

	for (int i = 0; i < NumSyncHandlers; i++)
	{
		auto syncHandler = m_syncHandler[i];
		if (syncHandler->OnIdaNotification(notification))
			return;
	}

	// Unhandled Notification
	// idp
	if (notification.type == IdaNotificationType::idp)
	{
		switch (notification.code)
		{
			case processor_t::undefine:
			case processor_t::make_code:
			case processor_t::make_data:
			case processor_t::move_segm:
			case processor_t::renamed:
			case processor_t::add_func:
			case processor_t::del_func:
			case processor_t::set_func_start:
			case processor_t::set_func_end:
			//case processor_t::validate_flirt_func:
			case processor_t::add_cref:
			case processor_t::add_dref:
			case processor_t::del_cref:
			case processor_t::del_dref:
			//case processor_t::auto_empty:
			//case processor_t::auto_queue_empty:
			//case processor_t::auto_empty_finally:
			{
				_unhandled_notification(idp_events_strings[notification.code]);
				return;
			}

			default:
				return;
		}
	}

	// idb
	if (notification.type == IdaNotificationType::idb)
	{
		switch (notification.code)
		{
			case idb_event::byte_patched:
			case idb_event::cmt_changed:
			case idb_event::ti_changed:
			case idb_event::op_ti_changed:
			case idb_event::op_type_changed:
			case idb_event::enum_created:
			case idb_event::enum_deleted:
			case idb_event::enum_bf_changed:
			case idb_event::enum_renamed:
			case idb_event::enum_cmt_changed:
			//case idb_event::enum_member_created:
			case idb_event::enum_const_created:
			//case idb_event::enum_member_deleted:
			case idb_event::enum_const_deleted:
			case idb_event::struc_created:
			case idb_event::struc_deleted:
			case idb_event::struc_renamed:
			case idb_event::struc_expanded:
			case idb_event::struc_cmt_changed:
			case idb_event::struc_member_created:
			case idb_event::struc_member_deleted:
			case idb_event::struc_member_renamed:
			case idb_event::struc_member_changed:
			case idb_event::thunk_func_created:
			case idb_event::func_tail_appended:
			case idb_event::func_tail_removed:
			case idb_event::tail_owner_changed:
			case idb_event::func_noret_changed:
			case idb_event::segm_added:
			case idb_event::segm_deleted:
			case idb_event::segm_start_changed:
			case idb_event::segm_end_changed:
			case idb_event::segm_moved:
			//case idb_event::area_cmt_changed:
			/*case idb_event::changing_cmt:
			case idb_event::changing_ti:
			case idb_event::changing_op_ti:
			case idb_event::changing_op_type:
			case idb_event::deleting_enum:
			case idb_event::changing_enum_bf:
			case idb_event::renaming_enum:
			case idb_event::changing_enum_cmt:
			//case idb_event::deleting_enum_member:
			case idb_event::deleting_enum_const:
			case idb_event::deleting_struc:
			case idb_event::renaming_struc:
			case idb_event::expanding_struc:
			case idb_event::changing_struc_cmt:
			case idb_event::deleting_struc_member:
			case idb_event::renaming_struc_member:
			case idb_event::changing_struc_member:
			case idb_event::removing_func_tail:
			case idb_event::deleting_segm:
			case idb_event::changing_segm_start:
			case idb_event::changing_segm_end:
			case idb_event::changing_area_cmt:
			case idb_event::changing_segm_name:
			case idb_event::changing_segm_class:
			case idb_event::segm_name_changed:
			case idb_event::segm_class_changed:*/
			{
				_unhandled_notification(idb_events_strings[notification.code]);
				return;
			}

			default:
				return;
		}
	}
}

IdbUpdateData* SyncManager::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	IdbUpdateData updateDataHeader;

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

NetworkBufferT<BasePacket>* SyncManager::EncodePacket(IdbUpdateData* updateData)
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
	{
		delete packet;
		return nullptr;
	}

	// Encode
	syncHandler->EncodePacket(packet, updateData);

	// Done
	return packet;
}