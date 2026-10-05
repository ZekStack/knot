#pragma once

#include "../Knot.h"
#include "KnotMutex.h"

namespace zek::knot {

struct KnotImpl {
	KnotImpl() noexcept : mutex(KnotMutex::create()) {
	}

	KnotConfig config{};
	bool initialized = false;
	KnotMutex mutex;
};

} // namespace zek::knot
