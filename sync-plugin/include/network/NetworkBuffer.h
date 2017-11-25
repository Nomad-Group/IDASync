#pragma once
#include <stdint.h>

class NetworkBuffer
{
protected:
	int8_t* m_buffer;
	size_t m_stActualSize = 0;

	size_t m_stSize = 0;

	size_t m_stOffset = 0;

public:
	NetworkBuffer(size_t stSize = 256);
	~NetworkBuffer();

	// Buffer
	virtual size_t Resize(size_t stNewSize);
	inline size_t GetSize() const { return m_stSize; };
	inline size_t GetActualBufferSize() const { return m_stActualSize; };
	inline int8_t* GetBuffer() { return m_buffer; }

	// Offset
	inline size_t GetOffset() const { return m_stOffset; };
	void SetOffset(size_t stOffset);

	// Read
	bool Read(int8_t*, size_t);
	template <typename T> inline bool Read(T* out, size_t stSize = sizeof(T)) { return Read((int8_t*)out, stSize); };

	const char* ReadString();
	void WriteString(const char*);

	// Write
	void Write(int8_t*, size_t);
	template <typename T> inline void Write(T* in, size_t stSize = sizeof(T)) { Write((int8_t*)in, stSize); };
	template <typename T> inline void Write(T in, size_t stSize = sizeof(T)) { Write((int8_t*) &in, stSize); };

	int8_t* WritePtr(size_t); // returns buffer[offset] and reserves x
};

template <class T>
class NetworkBufferT : public NetworkBuffer
{
public:
	using Type = T;

	NetworkBufferT() : NetworkBuffer(max(sizeof(T), 256))
	{
		m_stOffset = sizeof(T);
		m_stSize = sizeof(T);

		t = (T*) m_buffer;
	}

	virtual size_t Resize(size_t stNewSize) override
	{
		auto stOldSize = NetworkBuffer::Resize(stNewSize);
		t = (T*) m_buffer;
		return stOldSize;
	}

	T* t;
};