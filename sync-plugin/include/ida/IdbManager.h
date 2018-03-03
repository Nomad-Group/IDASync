#pragma once
#include <stdint.h>

#include <ida.hpp>
#include <netnode.hpp>

class IdbManager
{
private:
	netnode m_persistentData;
	enum class PersistentDataIndex : nodeidx_t
	{
		SyncPluginVersion,
		IdbVersion
	};

	static const char STRUCT_NAMES_TAG = 'T';

public:
	IdbManager();
	~IdbManager() = default;

	// Initialize
	bool Initialize();

	// Persistent Data
	bool HasPersistentData();

	// Version
	uint32_t GetVersion();
	bool SetVersion(uint32_t);

	// Structs Info
	void StoreStructName(tid_t, const std::string&);
	std::string GetStructName(tid_t);
};

extern IdbManager* g_idb;