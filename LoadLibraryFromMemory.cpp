#include <windows.h>

typedef BOOL(WINAPI* DLLMAIN)(HMODULE, DWORD, LPVOID);

typedef struct _MODULE {
	LPVOID image_base;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
}MODULE, *PMODULE;

BOOL IsValidePE(LPVOID module) {
	if (!module) {
		SetLastError(9);
		return FALSE;
	}

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module + dos_header->e_lfanew);

#ifdef _WIN64
	if (nt_header->OptionalHeader.Magic != 0x020B) {
		SetLastError(222);
		return FALSE;
	}
#elif _WIN32
	if (nt_header->OptionalHeader.Magic != 0x010B) {
		SetLastError(222);
		return FALSE;
	}
#endif

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_header->Signature != IMAGE_NT_SIGNATURE) {
		SetLastError(191);
		return FALSE;
	}
	if (!(nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		SetLastError(190);
		return FALSE;
	}
	return TRUE;
}

LPVOID AllocModule(LPVOID module) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((LPBYTE)module + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	LPVOID image = VirtualAlloc((LPVOID)nt_header->OptionalHeader.ImageBase,
		nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (image) {
		if (memcpy(image, module, nt_header->OptionalHeader.SizeOfHeaders)) {
			for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
				memcpy((LPBYTE)image + section_header[i].VirtualAddress,
					(LPBYTE)module + section_header[i].PointerToRawData,
					section_header[i].SizeOfRawData);
			}
			return image;
		}
	}
	return NULL;
}

DWORD WINAPI LoadModule(PMODULE module) {
	PIMAGE_BASE_RELOCATION base_relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)module->image_base + module->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)module->image_base + module->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

#ifdef _WIN64
	DWORD64 delta = (DWORD64)((LPBYTE)module->image_base - module->nt_header->OptionalHeader.ImageBase);
#elif _WIN32
	DWORD32 delta = (DWORD32)((LPBYTE)module->image_base - module->nt_header->OptionalHeader.ImageBase);
#endif
	
	while (base_relocation->VirtualAddress) {
		if (base_relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
		#ifdef _WIN64
			DWORD64 count = ((base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		#elif _WIN32
			DWORD32 count = ((base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		#endif
			PWORD list = (PWORD)(base_relocation + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)module->image_base + (base_relocation->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		base_relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)base_relocation + base_relocation->SizeOfBlock);
	}

	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	while (import_descriptor->Characteristics) {
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)module->image_base + import_descriptor->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)module->image_base + import_descriptor->FirstThunk);

		HMODULE hModule = LoadLibraryA((LPCSTR)module->image_base + import_descriptor->Name);

		if (!hModule) {
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData) {
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
			#ifdef _WIN64
				DWORD64 func = (DWORD64)GetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
			#elif _WIN32
				DWORD32 func = (DWORD32)GetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
			#endif

				if (!func) {
					return false;
				}

				FirstThunk->u1.Function = func;
			}
			else {
				PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)module->image_base + OrigFirstThunk->u1.AddressOfData);

			#ifdef _WIN64
				DWORD64 func = (DWORD64)GetProcAddress(hModule, (LPCSTR)import_by_name->Name);
			#elif _WIN32
				DWORD32 func = (DWORD32)GetProcAddress(hModule, (LPCSTR)import_by_name->Name);
			#endif

				if (!func) {
					return false;
				}

				FirstThunk->u1.Function = func;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		import_descriptor++;
	}

	if (module->nt_header->OptionalHeader.AddressOfEntryPoint) {
		return ((DLLMAIN)((LPBYTE)module->image_base + module->nt_header->OptionalHeader.AddressOfEntryPoint))((HMODULE)module->image_base, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

HMODULE LoadLibraryFromMemory(LPVOID module) {
	if (!IsValidePE(module)) {
		return NULL;
	}

	MODULE module_struct{ 0 };
	module_struct.image_base = AllocModule(module);

	if (!module_struct.image_base) {
		SetLastError(12);
		return NULL;
	}

	module_struct.dos_header = (PIMAGE_DOS_HEADER)module_struct.image_base;
	module_struct.nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module_struct.image_base + module_struct.dos_header->e_lfanew);

	LoadModule(&module_struct);

	return (HMODULE)module_struct.image_base;
}