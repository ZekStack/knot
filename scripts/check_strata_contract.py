#!/usr/bin/env python3

from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

errors: list[str] = []

def require(path: str, text: str, message: str) -> None:
    content = (ROOT / path).read_text()
    if text not in content:
        errors.append(message)

def reject(pattern: str, message: str) -> None:
    regex = re.compile(pattern)
    for path in SRC.rglob("*"):
        if not path.is_file() or path.suffix not in {".h", ".hpp", ".cpp", ".inc"}:
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if regex.search(line):
                errors.append(f"{path.relative_to(ROOT)}:{number}: {message}: {line.strip()}")

require("src/Knot.h", "Strata::MemoryPolicy memory", "KnotConfig must expose Strata::MemoryPolicy")
require("src/Knot.h", "Strata::UniquePtr<KnotImpl>", "KnotImpl must use Strata ownership")
require(
    "src/Knot.h",
    "Strata::UniquePtr<KnotCompareOperationImpl>",
    "compare operation storage must use Strata ownership",
)
require(
    "src/internal/KnotMutex.h",
    "Strata::FreeRTOS::RecursiveMutex",
    "Knot mutex must use Strata FreeRTOS ownership",
)
require(
    "src/internal/KnotCryptoMbedTls.cpp",
    "Strata::create<HmacSha256Context>",
    "HMAC wrapper must use Strata allocation",
)

metadata = json.loads((ROOT / "library.json").read_text())
expected = "https://github.com/ZekStack/strata.git#v0.1.3"
if metadata.get("dependencies", {}).get("Strata") != expected:
    errors.append("library.json must pin Strata v0.1.3")

reject(r"\bheap_caps_", "direct ESP-IDF heap allocation is forbidden")
reject(r"\bMALLOC_CAP_", "direct ESP-IDF heap capability use is forbidden")
reject(r"\bps_malloc\b", "direct PSRAM allocation is forbidden")
reject(r"\bxSemaphoreCreate(?:Mutex|RecursiveMutex)\s*\(", "owned mutex creation must use Strata")
reject(r"\bvSemaphoreDelete\s*\(", "owned semaphore deletion must use Strata")
reject(r"(?<![:\w])new\s*(?:\(|\[|\w)", "direct new ownership is forbidden")
reject(r"(?<![:\w])delete\s*(?:\[\s*\])?\s*\w", "direct delete ownership is forbidden")
reject(r"\bstd::make_unique\b|\bstd::make_shared\b", "standard heap ownership must use Strata")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("Strata ownership contract passed")
