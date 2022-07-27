#include <windows.h>
#include <Psapi.h>

#define InRange(x, a, b) (x >= a && x <= b)
#define getBit(x) (InRange((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA): (InRange(x, '0', '9') ? x - '0': 0))
#define getByte(x) (getBit(x[0]) << 4 | getBit(x[1]))

uintptr_t sigscan(const uintptr_t& start_address, const uintptr_t& end_address, const char* target_pattern) {
    const char* pattern = target_pattern;
    uintptr_t first_match = 0;

    for (uintptr_t position = start_address; position < end_address; position++) {
        if (!*pattern)
            return first_match;


        const unsigned char pattern_current = *reinterpret_cast<const unsigned char*>(pattern);
        const unsigned char memory_current = *reinterpret_cast<const unsigned char*>(position);


        if (pattern_current == '\?' || memory_current == getByte(pattern)) {
            if (!first_match)
                first_match = position;

            if (!pattern[2])
                return first_match;

            pattern += pattern_current != '\?' ? 3 : 2;

        }
        else {
            pattern = target_pattern;
            first_match = 0;
        }

    }
    return 0;
}

void* memcpy_nocrt(void* dest, const void* src, unsigned __int64 count)
{
    char* char_dest = (char*)dest;
    char* char_src = (char*)src;
    if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
    {
        while (count > 0)
        {
            *char_dest = *char_src;
            char_dest++;
            char_src++;
            count--;
        }
    }
    else
    {
        char_dest = (char*)dest + count - 1;
        char_src = (char*)src + count - 1;
        while (count > 0)
        {
            *char_dest = *char_src;
            char_dest--;
            char_src--;
            count--;
        }
    }
    return dest;
}

void patch(void* address, void* bytes, int byteSize)
{
    DWORD protection;
    VirtualProtect(address, byteSize, PAGE_EXECUTE_READWRITE, &protection);
    memcpy_nocrt(address, bytes, byteSize);
    VirtualProtect(address, byteSize, protection, &protection);
}