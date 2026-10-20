#pragma once

// Minimal precompiled header for qproto.
// Unlike classic precompiled.h (which pulls in Metamod/HLSDK/Steam SDK/ReHLDS API
// headers), qproto's crypto layer (Rijndael.cpp, sha2.cpp) has no engine dependency at
// all, so this stays deliberately small. Engine-facing files include what they need
// directly instead of funneling everything through here.

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

#include "qproto/qproto_shared.h"
#include "qproto/qproto_bits.h"

#include "qproto/sha2.h"
#include "qproto/Rijndael.h"
