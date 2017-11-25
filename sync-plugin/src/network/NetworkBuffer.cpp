#include "network/NetworkBuffer.h"
#include <string>

NetworkBuffer::NetworkBuffer(size_t stSize)
{
	Resize(stSize);
}

NetworkBuffer::~NetworkBuffer()
{
	delete m_buffer;
}

size_t NetworkBuffer::Resize(size_t stNewSize)
{
	if (m_stActualSize == stNewSize)
		return m_stActualSize;

	// Size
	size_t stOldSize = m_stActualSize;
	m_stActualSize = stNewSize;

	// Buffer
	m_buffer = (int8_t*) realloc(m_buffer, m_stActualSize);
	if(stNewSize > stOldSize)
		memset(&m_buffer[stOldSize], 0, stNewSize - stOldSize);

	return stOldSize;
}

void NetworkBuffer::SetOffset(size_t stOffset)
{
	if (stOffset < m_stSize)
		m_stOffset = stOffset;
}

bool NetworkBuffer::Read(int8_t* memory, size_t stSize)
{
	if (memory == nullptr || (m_stOffset + stSize) >= m_stActualSize)
		return false;

	memcpy(memory, &m_buffer[m_stOffset], stSize);
	m_stOffset += stSize;

	return true;
}

const char* NetworkBuffer::ReadString()
{
	if (m_stOffset >= m_stActualSize)
		return nullptr;

	size_t stStringLength = 0;
	while(m_stOffset < m_stActualSize)
	{
		if (m_buffer[m_stOffset] == '\0')
			return (const char*)&m_buffer[m_stOffset - stStringLength];

		stStringLength++;
		m_stOffset++;
	}

	// Shit, string is not null-terminated. we failed
	return nullptr;
}

void NetworkBuffer::WriteString(const char* str)
{
	if (str == nullptr)
		return;

	auto stringSize = strlen(str) + 1;
	auto requiredSize = m_stOffset + stringSize;
	if (requiredSize > m_stActualSize)
		Resize(requiredSize);

	memcpy(&m_buffer[m_stOffset], str, stringSize);

	m_stOffset += stringSize;
	m_stSize += stringSize;
}

void NetworkBuffer::Write(int8_t* memory, size_t stSize)
{
	auto requiredSize = m_stOffset + stSize;
	if (requiredSize > m_stActualSize)
		Resize(requiredSize);

	if (memory)
		memcpy(&m_buffer[m_stOffset], memory, stSize);
	else
		memset(&m_buffer[m_stOffset], 0, stSize);

	m_stOffset += stSize;
	m_stSize += stSize;
}

int8_t* NetworkBuffer::WritePtr(size_t stSize)
{
	auto requiredSize = m_stOffset + stSize;
	if (requiredSize > m_stActualSize)
		Resize(requiredSize);

	m_stOffset += stSize;
	m_stSize += stSize;

	return &m_buffer[m_stOffset - stSize];
}