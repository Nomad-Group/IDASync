#include "ida/IdbManager.h"

IdbManager* g_idb = nullptr;

IdbManager::IdbManager()
{}

bool IdbManager::Initialize()
{
	bool newlyCreated = m_persistentData.create("$ syncplugin_data");
	if (newlyCreated)
	{
		static const uint32_t SyncPlugin_VersionIndex = 0;
		if (!m_persistentData.supset((uint32_t)PersistentDataIndex::SyncPluginVersion, &SyncPlugin_VersionIndex, sizeof(SyncPlugin_VersionIndex)))
			return false;

		static const uint32_t InitialVersionIndex = 0;
		if (!SetVersion(InitialVersionIndex))
			return false;
	}

	return true;
}

bool IdbManager::HasPersistentData()
{
	bool newlyCreated = m_persistentData.create("$ syncplugin_data");
	if (newlyCreated) {
		netnode_kill(&m_persistentData);

		return false;
	}

	return true;
}

uint32_t IdbManager::GetVersion()
{
	uint32_t uiVersion = 0;
	m_persistentData.supval((uint32_t)PersistentDataIndex::IdbVersion, &uiVersion, sizeof(uint32_t));

	return uiVersion;
}

bool IdbManager::SetVersion(uint32_t idx)
{
	return m_persistentData.supset((uint32_t)PersistentDataIndex::IdbVersion, &idx, sizeof(uint32_t));
}