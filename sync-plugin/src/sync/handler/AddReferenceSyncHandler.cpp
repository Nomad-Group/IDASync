#include "sync/handler/AddReferenceSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool AddReferenceSyncHandler::ApplyUpdateImpl(AddReferenceSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptrFrom) + "-" + number2hex(updateData->ptrTo) + " add reference");

	switch (updateData->referenceType)
	{
	case ReferenceType::Code:
		return add_cref(static_cast<ea_t>(updateData->ptrFrom), static_cast<ea_t>(updateData->ptrTo), (cref_t) updateData->referenceDataType);

	case ReferenceType::Data:
		return add_dref(static_cast<ea_t>(updateData->ptrFrom), static_cast<ea_t>(updateData->ptrTo), (dref_t)updateData->referenceDataType);

	default:
		return false;
	}
}

bool AddReferenceSyncHandler::ShouldHandleNotification(IdaNotification& notification)
{
	return
		 notification.type == IdaNotificationType::idp &&
		(notification.code == processor_t::add_cref || notification.code == processor_t::add_dref);
}

bool AddReferenceSyncHandler::HandleNotification(IdaNotification& notification, AddReferenceSyncUpdateData* updateData)
{
	updateData->referenceType = notification.code == processor_t::add_cref ? ReferenceType::Code : ReferenceType::Data;

	updateData->ptrFrom = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	updateData->ptrTo = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	updateData->referenceDataType = va_arg(notification.args, uint32_t); // cref_t / dref_t

	return true;
}

void AddReferenceSyncHandler::DecodePacketImpl(AddReferenceSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->referenceType);

	packet->Read(&updateData->ptrFrom);
	packet->Read(&updateData->ptrTo);
	packet->Read(&updateData->referenceDataType);
}

void AddReferenceSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, AddReferenceSyncUpdateData* updateData)
{
	packet->Write(&updateData->referenceType);

	packet->Write(&updateData->ptrFrom);
	packet->Write(&updateData->ptrTo);
	packet->Write(&updateData->referenceDataType);
}