#include "sync/NameSyncHandler.h"

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>

bool NameSyncHandler::ApplyUpdate(IdbUpdate* _updateData)
{
	auto updateData = (NameSyncUpdateData*)_updateData;
	return set_name(static_cast<ea_t>(updateData->ptr), updateData->name.c_str(), SN_NOWARN);// (packet->local ? SN_LOCAL : 0) | SN_NOWARN));
}

IdbUpdate* NameSyncHandler::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	auto updateData = new NameSyncUpdateData();
	
	// Data
	packet->Read(&updateData->ptr);

	auto str = packet->ReadString();
	if (str == nullptr)
		return nullptr;
	
	updateData->name = str;
	return updateData;
}

bool NameSyncHandler::EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdate* _updateData)
{
	auto updateData = (NameSyncUpdateData*)_updateData;

	// Data
	packet->Write(updateData->ptr);
	packet->WriteString(updateData->name.c_str());

	return true;
}