#pragma once
#include "ISyncHandler.h"

struct IdbUpdateData
{
	uint32_t version;
	SyncType syncType;
};