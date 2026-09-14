#pragma once

// Minimal precompiled header for qproto.
// Unlike classic's precompiled.h (which pulls in Metamod/HLSDK/Steam SDK/ReHLDS API
// headers), qproto's crypto layer (Rijndael.cpp, sha2.cpp) has no engine dependency at
// all, so this stays deliberately small. Engine-facing files include what they need
// directly instead of funneling everything through here.

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

#include "classic_shared.h"
#include "qproto_bits.h"

#include "sha2.h"
#include "Rijndael.h"
