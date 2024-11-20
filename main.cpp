#include <LIEF/LIEF.hpp>
#include <vector>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <keystone/keystone.h>
#include <format>
#include "utils.hpp"

#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
using namespace LIEF;
using namespace LIEF::PE;

typedef void(*Func)(void);

int main() {
	std::string input_file = "packed.exe";
	std::string output_file = "recompiled.exe";

	// parse the input file as a PE binary
	std::unique_ptr<PE::Binary> binary = LIEF::PE::Parser::parse(input_file);
	if (!binary) {
		std::cerr << "Failed to load PE file!" << std::endl;
		return 1;
	}

	// add manual imports here
	AddFunctions("KERNEL32.dll", binary);
	AddFunctions("NTDLL.dll", binary);
	AddFunctions("user32.dll", binary);

	// rebuild the binary with updated imports
	LIEF::PE::Builder builder(binary.get());
	builder.build_imports(true);
	builder.patch_imports(true);
	builder.build();
	builder.write(output_file);

	// re-parse the output file for further modifications
	binary = LIEF::PE::Parser::parse(output_file);

	// find obfuscated imports using a custom function
	std::vector<obfuscated_import_t> obfuscated_imports = FindObfuscatedImports(binary->get_content_from_virtual_address(0x140001000, 0x5000).data(), 0x140001000, 0x5000);
	if (obfuscated_imports.size() <= 0)
		return -1;

	// resolve the obfuscated imports
	ResolveObfuscatedImports(obfuscated_imports, binary);

	// iterate through each obfuscated import and patch the binary
	for (auto obfuscated_import : obfuscated_imports)
	{
		if (!obfuscated_import.api)
			continue;

		std::vector<unsigned char> machine_code;

		ks_engine* ks;
		unsigned char* encode;
		size_t size;
		size_t total_size = 0;
		size_t count;
		uint64_t address = obfuscated_import.entry;

		// initialize keystone engine for assembling
		auto k_err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
		if (k_err != KS_ERR_OK) {
			std::cerr << "Failed to initialize Keystone: " << ks_strerror(k_err) << std::endl;
			return -1;
		}

		for (auto param : obfuscated_import.params)
		{
			param.str = ModifyRipOffset(param.str, param.offset + (param.addr - address - total_size));
			if (ks_asm(ks, param.str.c_str(), address + total_size, &encode, &size, &count) != KS_ERR_OK)
			{
				std::cerr << "Failed to assemble code: " << ks_strerror(ks_errno(ks)) << std::endl;
				ks_close(ks);
				return -1;
			}
			total_size += size;

			for (size_t i = 0; i < size; i++) {
				machine_code.push_back(encode[i]);
			}

		}

		// generate assembly code to resolve API
		if (ks_asm(ks, std::format("mov rax, qword ptr ds:{};", obfuscated_import.api).c_str(), address + total_size, &encode, &size, &count) != KS_ERR_OK)
		{
			std::cerr << "Failed to assemble code: " << ks_strerror(ks_errno(ks)) << std::endl;
			ks_close(ks);
			return -1;
		}
		total_size += size;

		for (size_t i = 0; i < size; i++) {
			machine_code.push_back(encode[i]);
		}

		// generate assembly code for jump instruction
		if (ks_asm(ks, std::format("jmp {};", obfuscated_import.exit).c_str(), address + total_size, &encode, &size, &count) != KS_ERR_OK)
		{
			std::cerr << "Failed to assemble jump instruction: " << ks_strerror(ks_errno(ks)) << std::endl;
			ks_close(ks);
			return -1;
		}
		total_size += size;

		for (size_t i = 0; i < size; i++) {
			machine_code.push_back(encode[i]);
		}

		// close the keystone engine
		ks_close(ks);

		// patch the binary with the generated machine code
		binary->patch_address(obfuscated_import.entry, machine_code);
		binary->patch_address(obfuscated_import.entry + machine_code.size(), std::vector<uint8_t>(obfuscated_import.exit - obfuscated_import.entry - machine_code.size(), 0));
	}

	// finalize and write the updated binary
	builder = Builder(binary.get());
	builder.build_imports(false);
	builder.patch_imports(false);
	builder.build();
	builder.write(output_file);

	return 0;
}
