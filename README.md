# Lazy Import Deobfuscator - Proof of Concept

This project is a **Proof of Concept (PoC)**, and I do not plan to develop it further. It was created as a personal challenge to explore the concept of deobfuscating executables and rebuilding. Also it's my first auto deobfuscator ever i wrote.

The project successfully achieved its main goal: deobfuscating an executable obfuscated by lazy importer and rebuilding it into a functional, runnable binary. However, due to the variability in how lazy importer is implemented by different compilers, writing a fully automated deobfuscator is nearly impossible.

This repository is shared not for direct usage but as a foundation for others to build upon and adapt to their own needs.

---

## How It Works

This project was developed using **LIEF**, **Capstone**, and **Keystone** frameworks. Below is an overview of the process:

### 1. Analyzing Lazy Import Obfuscation
- Lazy importer typically obfuscate function calls by replacing direct API calls with hashed or encoded representations.
- I disassembled the binary to identify and analyze obfuscated function calls.
- Reverse-engineered the lazy import hashing algorithm.
- By studying lazy imports across binaries, I identified patterns common to their obfuscation mechanisms. However, this step often requires **manual intervention** as lazy imports vary significantly between compilers.

### 2. Resolving Function Calls
- Once the obfuscated lazy import traces were identified, I used the following steps:
  - Extracted necessary information (e.g., offsets, hashes) from the disassembled code.
  - Compared the extracted hashes with the hashes of functions in imported DLLs.
- **Caveat**: In many cases, lazy imports do not even leave behind the required DLLs, making dynamic analysis crucial. You may need to manually trace calls to identify which function is invoked and update the Import Address Table (IAT) accordingly.

### 3. Replacing Obfuscated Code
- After resolving the function calls:
  - I used **Keystone** to generate new assembly code that replaces the obfuscated lazy import calls with **direct API calls**.
  - The original obfuscated code was effectively eliminated and replaced.

However, even in an ideal scenario, significant manual analysis is often required due to the unique nature of each binary.

---

## Limitations

- **Compiler Dependency**: Lazy imports are highly compiler-dependent, meaning the structure and behavior of the obfuscated code can vary widely. 
- **Manual Effort**: Fully automating the deobfuscation process is impractical due to the variability in lazy import implementations.
- **Experimental Nature**: The disassembly and resolution processes may fail in some cases and require manual adjustments.

---

## Final Note

This PoC is intended as a **starting point for developers and researchers** who want to experiment with deobfuscation techniques. While it demonstrates the concept, it is not a fully reliable or polished tool. Feel free to adapt and improve upon it to suit your specific use case.

Happy hacking! 😊


### Obfuscated
```IDA Decompiler
for ( i = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink; ; i = i->Flink )
  {
    Flink = i[3].Flink;
    v6 = (struct _LIST_ENTRY *)((char *)Flink + *(unsigned int *)((char *)&Flink[8].Blink + SHIDWORD(Flink[3].Blink)));
    if ( v6 != Flink )
    {
      LODWORD(v7) = v6[1].Blink;
      if ( (_DWORD)v7 )
        break;
    }
LABEL_8:
    ;
  }
  while ( 1 )
  {
    v7 = (unsigned int)(v7 - 1);
    v8 = (char *)Flink + *(unsigned int *)((char *)&Flink->Flink + 4 * v7 + LODWORD(v6[2].Flink));
    v9 = -1365977033;
    v10 = *v8;
    v11 = v8 + 1;
    if ( v10 )
    {
      do
      {
        v9 = 16777619 * (v9 ^ v10);
        v10 = *v11++;
      }
      while ( v10 );
      if ( v9 == 1771347584 )
        break;
    }
    if ( !(_DWORD)v7 )
      goto LABEL_8;
  }
  hConsoleOutput = (HANDLE)((__int64 (__fastcall *)(__int64, char *, char *))((char *)Flink
                                                                            + *(unsigned int *)((char *)&Flink->Flink
                                                                                              + 4
                                                                                              * *(unsigned __int16 *)((char *)&Flink->Flink + 2 * v7 + HIDWORD(v6[2].Flink))
                                                                                              + HIDWORD(v6[1].Blink))))(
                             4294967285LL,
                             (char *)Flink + HIDWORD(v6[1].Blink),
                             v11);
```

### Deobfuscated
```IDA Decompiler
qword_140068E38 = (__int64)GetStdHandle(0xFFFFFFF5);
```
