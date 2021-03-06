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

std::string NetworkBuffer::ReadString()
{
	if (m_stOffset >= m_stActualSize)
		return std::string();

	size_t stStringLength = 0;
	while(m_stOffset < m_stActualSize)
	{
		if (m_buffer[m_stOffset] == '\0') {
			m_stOffset++;

			if (stStringLength == 0)
				return std::string();

			return std::string((const char*)&m_buffer[m_stOffset - stStringLength - 1]);
		}

		stStringLength++;
		m_stOffset++;
	}

	// Shit, string is not null-terminated. we failed
	return std::string();
}

bool NetworkBuffer::ReadBool()
{
	uint8_t val = 0;
	Read(&val);

	return val == 1;
}

void NetworkBuffer::WriteString(const std::string& str)
{
	if (str.empty())
	{
		Write<uint8_t>(0);
		return;
	}

	auto stringSize = str.length() + 1;
	auto requiredSize = m_stOffset + stringSize;
	if (requiredSize > m_stActualSize)
		Resize(requiredSize);

	memcpy(&m_buffer[m_stOffset], str.c_str(), stringSize);

	m_stOffset += stringSize;
	m_stSize += stringSize;
}

void NetworkBuffer::WriteBool(bool val)
{
	uint8_t nval = val == true ? 1 : 0;
	Write(&nval);
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