#include "sync/handler/MakeDataSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool MakeDataSyncHandler::ApplyUpdateImpl(MakeDataSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " make data");

	return do_data_ex(static_cast<ea_t>(updateData->ptr), (flags_t) updateData->flags, static_cast<asize_t>(updateData->len), BADNODE);
}

bool MakeDataSyncHandler::HandleNotification(IdaNotification& notification, MakeDataSyncUpdateData* updateData)
{
	updateData->ptr = static_cast<uint64_t>(va_arg(notification.args, ea_t));

	updateData->flags = va_arg(notification.args, uint32_t); // flags_t
	tid_t t = va_arg(notification.args, tid_t);
	if (t != BADNODE)
	{
		// Structs are not supported yet!
		// get_struc_name(&name, t);

		g_plugin->Log("ERROR: MakeDataSyncHandler - structs are not supported!");
		return false;
	}

	updateData->len = static_cast<uint64_t>(va_arg(notification.args, asize_t));

	return true;
}

void MakeDataSyncHandler::DecodePacketImpl(MakeDataSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
	packet->Read(&updateData->len);

	packet->Read(&updateData->flags);
}

void MakeDataSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, MakeDataSyncUpdateData* updateData)
{
	packet->Write(&updateData->ptr);
	packet->Write(&updateData->len);

	packet->Write(&updateData->flags);
}