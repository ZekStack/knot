#pragma once

#include "FreeRTOS.h"

#include <pthread.h>

struct StaticSemaphore_t {
	pthread_mutex_t mutex;
	int initialized;
};

using SemaphoreHandle_t = StaticSemaphore_t *;

inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *storage) {
	if (storage == nullptr) {
		return nullptr;
	}
	storage->initialized = 0;
	if (pthread_mutex_init(&storage->mutex, nullptr) != 0) {
		return nullptr;
	}
	storage->initialized = 1;
	return storage;
}

inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *storage) {
	if (storage == nullptr) {
		return nullptr;
	}
	storage->initialized = 0;
	pthread_mutexattr_t attributes;
	if (pthread_mutexattr_init(&attributes) != 0) {
		return nullptr;
	}
	const int typeResult = pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
	const int initResult =
	    typeResult == 0 ? pthread_mutex_init(&storage->mutex, &attributes) : typeResult;
	pthread_mutexattr_destroy(&attributes);
	if (initResult != 0) {
		return nullptr;
	}
	storage->initialized = 1;
	return storage;
}

inline void vSemaphoreDelete(SemaphoreHandle_t handle) {
	if (handle != nullptr && handle->initialized != 0) {
		pthread_mutex_destroy(&handle->mutex);
		handle->initialized = 0;
	}
}

inline int xSemaphoreTake(SemaphoreHandle_t handle, TickType_t) {
	if (handle == nullptr || handle->initialized == 0) {
		return pdFALSE;
	}
	return pthread_mutex_lock(&handle->mutex) == 0 ? pdTRUE : pdFALSE;
}

inline void xSemaphoreGive(SemaphoreHandle_t handle) {
	if (handle != nullptr && handle->initialized != 0) {
		pthread_mutex_unlock(&handle->mutex);
	}
}

inline int xSemaphoreTakeRecursive(SemaphoreHandle_t handle, TickType_t timeout) {
	return xSemaphoreTake(handle, timeout);
}

inline void xSemaphoreGiveRecursive(SemaphoreHandle_t handle) {
	xSemaphoreGive(handle);
}
