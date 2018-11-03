#include "sync/handler/UndefineSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool UndefineSyncHandler::ApplyUpdateImpl(UndefineSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " undefined");

	return del_items(static_cast<ea_t>(updateData->ptr), DELIT_SIMPLE);
}

bool UndefineSyncHandler::HandleNotification(IdaNotification& notification, UndefineSyncUpdateData* updateData)
{
	updateData->ptr = static_cast<uint64_t>(va_arg(notification.args, ea_t));

	return true;
}

void UndefineSyncHandler::DecodePacketImpl(UndefineSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
}

void UndefineSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, UndefineSyncUpdateData* updateData)
{
	packet->Write(&updateData->ptr);
}