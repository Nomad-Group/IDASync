#include "sync/handler/ItemCommentSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool ItemCommentSyncHandler::ApplyUpdateImpl(ItemCommentSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " got comment " + updateData->text);

	return set_cmt(static_cast<ea_t>(updateData->ptr), updateData->text.c_str(), updateData->repeatable);
}

bool ItemCommentSyncHandler::HandleNotification(IdaNotification& notification, ItemCommentSyncUpdateData* updateData)
{
	// Args
	ea_t ea = va_arg(notification.args, ea_t);
	bool rep = va_arg(notification.args, int) != 0;

	// Update
	updateData->ptr = static_cast<uint64_t>(ea);
	updateData->repeatable = rep;

	// Comment Text
	size_t stSize = get_cmt(ea, rep, nullptr, 0) + 1;
	if (stSize == -1)
		return false;

	if (stSize > 0)
	{
		updateData->text.resize(stSize);
		get_cmt(ea, rep, &updateData->text.front(), stSize);
	}

	// Send
	return true;
}

void ItemCommentSyncHandler::DecodePacketImpl(ItemCommentSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
	updateData->repeatable = packet->ReadBool();
	updateData->text = packet->ReadString();
}

void ItemCommentSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, ItemCommentSyncUpdateData* updateData)
{
	packet->Write(updateData->ptr);
	packet->Write(updateData->repeatable);
	packet->WriteString(updateData->text);
}