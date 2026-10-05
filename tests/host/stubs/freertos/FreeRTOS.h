#pragma once

#define configSUPPORT_STATIC_ALLOCATION 1
#define configUSE_MUTEXES 1
#define configUSE_RECURSIVE_MUTEXES 1

using TickType_t = unsigned int;

constexpr TickType_t portMAX_DELAY = 0xffffffffu;
constexpr int pdTRUE = 1;
constexpr int pdFALSE = 0;
