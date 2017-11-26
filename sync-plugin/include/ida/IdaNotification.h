#pragma once
#include <ida.hpp>
#include <idp.hpp>

enum class IdaNotificationType
{
	idb,	// 
	idp,	// processor_t
};

struct IdaNotification
{
	IdaNotificationType type;
	int code;

	va_list args;
};