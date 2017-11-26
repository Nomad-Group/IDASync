#include "sync/handler/ItemCommentSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool ItemCommentSyncHandler::ApplyUpdate(IdbUpdate* _updateData)
{
	auto updateData = (ItemCommentSyncUpdateData*)_updateData;
	g_plugin->Log(number2hex(updateData->ptr) + " got comment " + updateData->text);

	return set_cmt(static_cast<ea_t>(updateData->ptr), updateData->text.c_str(), updateData->repeatable);
}

bool ItemCommentSyncHandler::OnIdaNotification(IdaNotification& notification)
{
	// Renamed Notification
	if (notification.type != IdaNotificationType::idb || notification.code != idb_event::cmt_changed)
		return false;

	// Args
	ea_t ea = va_arg(notification.args, ea_t);
	bool rep = va_arg(notification.args, int) != 0;

	// Update
	auto update = new ItemCommentSyncUpdateData();
	update->syncType = SyncType::ItemComment;

	update->ptr = static_cast<uint64_t>(ea);
	update->repeatable = rep;

	// Comment Text
	size_t stSize = get_cmt(ea, rep, nullptr, 0) + 1;
	if (stSize == -1)
	{
		delete update;
		return false;
	}

	if (stSize > 0)
	{
		update->text.resize(stSize);
		get_cmt(ea, rep, &update->text.front(), stSize);
	}

	// Send
	g_syncManager->SendUpdate(update);
	return true;
}

IdbUpdate* ItemCommentSyncHandler::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	auto updateData = new ItemCommentSyncUpdateData();

	// Data
	packet->Read(&updateData->ptr);
	updateData->repeatable = packet->ReadBool();
	updateData->text = packet->ReadString();

	return updateData;
}

bool ItemCommentSyncHandler::EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdate* _updateData)
{
	auto updateData = (ItemCommentSyncUpdateData*)_updateData;

	// Data
	packet->Write(updateData->ptr);
	packet->Write(updateData->repeatable);
	packet->WriteString(updateData->text.c_str());

	return true;
}