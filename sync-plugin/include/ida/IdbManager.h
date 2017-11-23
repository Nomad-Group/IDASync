#pragma once
#include <stdint.h>

#include <ida.hpp>
#include <netnode.hpp>

class IdbManager
{
private:
	netnode m_persistentData;
	enum class PersistentDataIndex : uint32_t
	{
		SyncPluginVersion,
		IdbVersion
	};

public:
	IdbManager();
	~IdbManager() = default;

	// Initialize
	bool Initialize();

	// Persistent Data
	uint32_t GetVersion();
	bool SetVersion(uint32_t);
};

extern IdbManager* g_idb;