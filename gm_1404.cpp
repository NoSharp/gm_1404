#include "Interface.h"
#include "Memory.h"
#include <Windows.h>
#include <direct.h>


// A naive approach to fixing the Source Exploit plaguing Source.
bool RUNNING_TEST = true;

#pragma warning(disable:4996)

GMOD_MODULE_OPEN()
{

    DWORD engineAddr = Memory::GetAddress("engine.dll", Memory::SIG1404, Memory::MASK1404) - Memory::OFFSET1404;
    BYTE* nops = Memory::GenerateNops(Memory::NOP1404 - 1);
    Memory::WriteMemory(nops, Memory::NOP1404 - 1, engineAddr);
	
	return 0;
}
GMOD_MODULE_CLOSE()
{
	return 0;
}
