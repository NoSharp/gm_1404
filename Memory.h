#include "Windows.h"
#include <Psapi.h>
#include <iostream>

#pragma once
namespace Memory
{
	const char* SIG1404 = "\x32\xC0\x5F\x5E\x5B\x8B\xE5\x5D\xC3\x51";
	const char* MASK1404 = "xxxxxxxxxx";
	const int OFFSET1404 = -0xE;
	const int NOP1404 = 0x18;
	
	// Small function to allow me to generate 15 NOPS semi-dynamically.
	BYTE* GenerateNops(int amount)
	{
		BYTE* nops = new BYTE[amount];
		for (int i=0; i < amount; i++)
		{
			nops[i] = 0x90;
		}
		return nops;
	}
	
	// Get's the module info duh.
	MODULEINFO GetModuleInfo(const char* mod_name)
	{
		//VMDOLPHIN_BLACK_START
		MODULEINFO info;
		HMODULE h_mod = GetModuleHandle(mod_name);
		GetModuleInformation(GetCurrentProcess(), h_mod, &info, sizeof(MODULEINFO));
		//VMDOLPHIN_BLACK_END
		return info;
	}

	// It take no credit for this signature finding method.
	// Credit to GuidedHacking
	DWORD GetAddress(const char* mod_name, const char* pattern, const char* mask)
	{
		DWORD BASE_ADDR = (DWORD)GetModuleInfo("gmod.exe").EntryPoint;
		MODULEINFO info = GetModuleInfo(mod_name);

		DWORD base = (DWORD)GetModuleHandleA(mod_name);
		DWORD size = (DWORD)info.SizeOfImage;

		DWORD pattern_length = (DWORD)strlen(mask);

		for (DWORD i = 0; i < size - pattern_length; i++)
		{
			bool found = true;
			for (DWORD j = 0; j < pattern_length; j++)
			{
				found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
			}

			if (found)
				return  base + i;
		}
		return 0;

	}

	bool WriteMemory(BYTE bytes[], int amount, DWORD address)
	{
		DWORD oldProt;
		VirtualProtect((LPVOID)address, sizeof(byte) * amount, PAGE_EXECUTE_READWRITE, &oldProt);

		for (int i = 0; i < amount; i++)
		{
			byte val = bytes[i];
			memset((void*)(address + i), val, sizeof(BYTE));
			//printf("Byte[%x]: 0x%x", i, val);
		}


		DWORD temp;
		VirtualProtect((LPVOID)address, sizeof(byte) * amount, oldProt, &temp);
		return 1;
	}
}
