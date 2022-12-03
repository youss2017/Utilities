#pragma once
#include <cstdint>
#include <vector>

#include <Windows.h> // VirtualAllocEx

namespace ut
{
	inline size_t DefaultMemoryCtxCount = 8196ull;
	inline size_t HeapBlockSize = 8192ull * 1024ull;

	struct Memory {
		const int8_t* Ptr;
		constexpr size_t size() const { return _size; }
		constexpr size_t id() const { return _id; }

		Memory(int8_t* ptr, size_t size, size_t id)
			: Ptr(ptr), _size(size), _id(id)
		{}

	private:
		const size_t _id;
		const size_t _size;
	};

	struct MemoryCtx {
		size_t MemoryCount{};
		size_t NextMemoryIndex{};
		size_t MemoryHeapSize{};
		size_t MemoryHeapOffset{};
		int8_t* MemoryPage = nullptr;
		Memory* StaticallyAllocatedMemory = nullptr;
	};

	class AllocateCtx {
	public:
		MemoryCtx* Allocate(size_t size);
		void Release(MemoryCtx* memory);
	private:
		std::vector<MemoryCtx> _MemoryContexts;
	};

	namespace internal {
		thread_local static AllocateCtx Allocater;
	}

	MemoryCtx* AllocateMemory(size_t size)
	{
		return internal::Allocater.Allocate(size);
	}

	void ReleaseMemory(MemoryCtx* memory)
	{
		internal::Allocater.Release(memory);
	}

	MemoryCtx* AllocateCtx::Allocate(size_t size)
	{
		// 1) Is there an available memory context
		for (size_t i = 0; i < _MemoryContexts.size(); i++)
		{
			auto& ctx = _MemoryContexts[i];
			size_t available = ctx.MemoryHeapOffset - ctx.MemoryHeapSize;
			if (available < size) continue;
			auto pages = VirtualAllocEx(nullptr, nullptr, HeapBlockSize + DefaultMemoryCtxCount * sizeof(MemoryCtx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}
	}

	void AllocateCtx::Release(MemoryCtx* memory)
	{

	}

}
