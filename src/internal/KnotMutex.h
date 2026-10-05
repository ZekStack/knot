#pragma once

#include <strata/freertos/Mutex.h>

namespace zek::knot {

using KnotMutex = Strata::FreeRTOS::RecursiveMutex;

class KnotLock {
  public:
	KnotLock(KnotMutex &mutex, bool enabled)
	    : _mutex(mutex), _enabled(enabled), _locked(!enabled || mutex.lock()) {
	}

	~KnotLock() {
		if (_locked && _enabled) {
			_mutex.unlock();
		}
	}

	KnotLock(const KnotLock &) = delete;
	KnotLock &operator=(const KnotLock &) = delete;

	explicit operator bool() const {
		return _locked;
	}

  private:
	KnotMutex &_mutex;
	bool _enabled = true;
	bool _locked = false;
};

} // namespace zek::knot
