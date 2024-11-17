#pragma once
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <capstone/capstone.h>
#include <iostream>
#include <LIEF/LIEF.hpp>

using namespace LIEF;
using namespace LIEF::PE;

class obfuscated_import_t
{
public:
    uint64_t entry = 0;
    uint64_t exit = 0;
    uint64_t api = 0;

    uint64_t offset = 0;
    uint64_t prime = 0;
    uint64_t hash = 0;
    bool requires_manual = false;
};

std::vector<obfuscated_import_t> FindObfuscatedImports(uint8_t* address, uint64_t virtual_addr, size_t size)
{
    std::vector<obfuscated_import_t> imports;

    csh handle;
    cs_opt_mem mem_options;
    mem_options.malloc = malloc;  // use malloc function
    mem_options.calloc = calloc;  // use calloc function
    mem_options.realloc = realloc; // use realloc function
    mem_options.free = free;      // use free function
    mem_options.vsnprintf = vsnprintf; // use vsnprintf function

    if (cs_option(NULL, CS_OPT_MEM, (size_t)&mem_options) != CS_ERR_OK)
    {
        return imports;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Capstone initialization failed!" << std::endl;
        return imports;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = cs_disasm(handle, address, size, (uint64_t)virtual_addr, 0, &insn);

    if (count > 0)
    {
        for (size_t i = 0; i < count; i++)
        {
            if (strcmp(insn[i].mnemonic, "mov") == 0)
            {
                auto operands = insn[i].detail->x86.operands;
                if (operands[0].type == X86_OP_REG && operands[1].type == X86_OP_MEM && operands[1].mem.disp == 0x60)
                {
                    obfuscated_import_t obfuscated_import;
                    obfuscated_import.entry = insn[i].address;
                    std::cout << "entry: 0x" << std::hex << insn[i].address << " ";
                    int stage = 0;

                    for (int j = i; j < count; j++)
                    {
                        auto operands = insn[j].detail->x86.operands;

                        if (strcmp(insn[j].mnemonic, "mov") == 0)
                        {
                            if (insn[j].detail->x86.op_count && operands[0].type == X86_OP_REG &&
                                operands[0].reg == X86_REG_EDX && operands[1].type == X86_OP_IMM &&
                                stage == 0)
                            {
                                std::cout << "offset: " << std::hex << operands[1].imm << " ";
                                obfuscated_import.offset = operands[1].imm;
                                ++stage;
                            }
                        }
                        else if (strcmp(insn[j].mnemonic, "imul") == 0)
                        {
                            if (insn[j].detail->x86.op_count && operands[0].type == X86_OP_REG &&
                                operands[0].reg == X86_REG_EDX && operands[2].type == X86_OP_IMM &&
                                stage == 1)
                            {
                                std::cout << "prime: " << std::hex << operands[2].imm << " ";
                                obfuscated_import.prime = operands[2].imm;
                                ++stage;
                            }
                        }
                        else if (strcmp(insn[j].mnemonic, "cmp") == 0)
                        {
                            if (insn[j].detail->x86.op_count && operands[0].type == X86_OP_REG &&
                                operands[0].reg == X86_REG_EDX && operands[1].type == X86_OP_IMM &&
                                stage == 2)
                            {
                                std::cout << "hash: " << std::hex << operands[1].imm << " ";
                                obfuscated_import.hash = operands[1].imm;
                                ++stage;
                            }
                        }
                        else if (strcmp(insn[j].mnemonic, "add") == 0)
                        {
                            if (insn[j].detail->x86.op_count && operands[0].type == X86_OP_REG &&
                                (operands[0].reg == X86_REG_RAX || operands[0].reg == X86_REG_R9) &&
                                (operands[1].reg == X86_REG_R10 || operands[1].reg == X86_REG_R11)
                                && stage == 3)
                            {
                                if (strcmp(insn[j - 2].mnemonic, "jmp") != 0)
                                {
                                    std::cout << "exit: 0x" << std::hex << insn[j + 1].address << " ";
                                    obfuscated_import.exit = insn[j + 1].address;
                                    ++stage;
                                }
                            }
                        }
                        else if (strcmp(insn[j].mnemonic, "call") == 0)
                        {
                            if (insn[j].detail->x86.op_count && operands[0].type == X86_OP_REG &&
                                stage == 4)
                            {
                                if (operands[0].reg != X86_REG_RAX)
                                    obfuscated_import.requires_manual = true;

                                std::cout << "call: 0x" << std::hex << insn[j].address << std::endl;

                                ++stage;
                                imports.push_back(obfuscated_import);
                                break;
                            }
                        }
                    }
                }
            }
        }
        cs_free(insn, count);
    }
    else {
        std::cerr << "Disassembly failed!" << std::endl;
    }

    cs_close(&handle);
    return imports;
}

uint32_t hash(const std::string s, uint32_t offset, uint32_t prime)
{
    uint32_t h = offset;
    for (char c : s)
    {
        h ^= static_cast<uint32_t>(c); // xor character with hash
        h *= prime; // multiply by prime
        h &= 0xFFFFFFFF; // keep only lower 32 bits
    }
    return h;
}

void ResolveObfuscatedImports(std::vector<obfuscated_import_t>& obfuscated_imports, std::unique_ptr<PE::Binary>& binary)
{
    for (auto& obfuscated_import : obfuscated_imports)
    {
        obfuscated_import.api = NULL;
        for (auto dll : binary->imports())
        {
            for (auto entry : dll.entries())
            {
                if (hash(entry.name(), obfuscated_import.offset, obfuscated_import.prime) == obfuscated_import.hash)
                {
                    obfuscated_import.api = binary->optional_header().imagebase() + entry.iat_address();
                    if (obfuscated_import.requires_manual)
                        std::cout << "requires manual analysis: " << entry.name() << " : " << obfuscated_import.entry << std::endl;
                    else
                        std::cout << "resolved import : " << entry.name() << " : " << obfuscated_import.entry << std::endl;
                }
            }
        }

        if (obfuscated_import.api == NULL)
            std::cout << "unresolved import : " << obfuscated_import.entry << std::endl;
    }
}
