#include "sync/handler/DeleteReferenceSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool DeleteReferenceSyncHandler::ApplyUpdateImpl(DeleteReferenceSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptrFrom) + "-" + number2hex(updateData->ptrTo) + " delete reference");

	switch (updateData->referenceType)
	{
	case ReferenceType::Code:
		del_cref(static_cast<ea_t>(updateData->ptrFrom), static_cast<ea_t>(updateData->ptrTo), updateData->expand);
		break;

	case ReferenceType::Data:
		del_dref(static_cast<ea_t>(updateData->ptrFrom), static_cast<ea_t>(updateData->ptrTo));
		break;

	default:
		return false;
	}

	return true;
}

bool DeleteReferenceSyncHandler::ShouldHandleNotification(IdaNotification& notification)
{
	return
		notification.type == IdaNotificationType::idp &&
		(notification.code == processor_t::del_cref || notification.code == processor_t::del_dref);
}

bool DeleteReferenceSyncHandler::HandleNotification(IdaNotification& notification, DeleteReferenceSyncUpdateData* updateData)
{
	updateData->referenceType = notification.code == processor_t::del_cref ? ReferenceType::Code : ReferenceType::Data;

	updateData->ptrFrom = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	updateData->ptrTo = static_cast<uint64_t>(va_arg(notification.args, ea_t));

	if (updateData->referenceType == ReferenceType::Code)
		updateData->expand = va_arg(notification.args, int) != 0;

	return true;
}

void DeleteReferenceSyncHandler::DecodePacketImpl(DeleteReferenceSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->referenceType);

	packet->Read(&updateData->ptrFrom);
	packet->Read(&updateData->ptrTo);

	if(updateData->referenceType == ReferenceType::Code)
		updateData->expand = packet->ReadBool();
}

void DeleteReferenceSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, DeleteReferenceSyncUpdateData* updateData)
{
	packet->Write(&updateData->referenceType);

	packet->Write(&updateData->ptrFrom);
	packet->Write(&updateData->ptrTo);

	if (updateData->referenceType == ReferenceType::Code)
		packet->WriteBool(updateData->expand);
}