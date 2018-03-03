#include "ida/IdbManager.h"
#include "SyncPlugin.h"

IdbManager* g_idb = nullptr;

IdbManager::IdbManager()
{}

bool IdbManager::Initialize()
{
	bool newlyCreated = m_persistentData.create("$ syncplugin_data");
	if (newlyCreated)
	{
		static const uint32_t SyncPlugin_VersionIndex = SyncPlugin::VERSION_NUMBER;
		if (!m_persistentData.supset((uint32_t)PersistentDataIndex::SyncPluginVersion, &SyncPlugin_VersionIndex, sizeof(SyncPlugin_VersionIndex)))
			return false;

		static const uint32_t InitialVersionIndex = 0;
		if (!SetVersion(InitialVersionIndex))
			return false;

		return true;
	}

	// Sync Plugin Version: Upgrade?
	uint32_t CurrentVersion = 0;
	m_persistentData.supval((uint32_t)PersistentDataIndex::SyncPluginVersion, &CurrentVersion, sizeof(CurrentVersion));

	if (CurrentVersion < SyncPlugin::VERSION_NUMBER)
	{
		// Upgrade
		static const uint32_t SyncPlugin_VersionIndex = SyncPlugin::VERSION_NUMBER;
		if (!m_persistentData.supset((uint32_t)PersistentDataIndex::SyncPluginVersion, &SyncPlugin_VersionIndex, sizeof(SyncPlugin_VersionIndex)))
			return false;

		// Upgrade Operations go here
		// ...

		// Done
		g_plugin->Log("Persistent Data: Upgraded version from " + std::to_string(CurrentVersion) + " to " + std::to_string(SyncPlugin::VERSION_NUMBER));
	}

	// Done
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