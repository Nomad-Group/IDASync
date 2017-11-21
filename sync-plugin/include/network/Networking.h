#pragma once
#include <string>

namespace Networking
{
	bool GlobalInit();
	void GlobalShutdown();

	std::string GetHardwareId();
}