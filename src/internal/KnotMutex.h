#pragma once

#if defined(ESP32)
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif

namespace zek::knot {

class KnotMutex {
  public:
	KnotMutex() {
#if defined(ESP32)
		_handle = xSemaphoreCreateRecursiveMutex();
#endif
	}

	~KnotMutex() {
#if defined(ESP32)
		if (_handle != nullptr) {
			vSemaphoreDelete(_handle);
			_handle = nullptr;
		}
#endif
	}

	KnotMutex(const KnotMutex &) = delete;
	KnotMutex &operator=(const KnotMutex &) = delete;

	bool lock() {
#if defined(ESP32)
		return _handle != nullptr && xSemaphoreTakeRecursive(_handle, portMAX_DELAY) == pdTRUE;
#else
		return true;
#endif
	}

	void unlock() {
#if defined(ESP32)
		if (_handle != nullptr) {
			xSemaphoreGiveRecursive(_handle);
		}
#endif
	}

  private:
#if defined(ESP32)
	SemaphoreHandle_t _handle = nullptr;
#endif
};

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
