# woody_woodpacker

## Table of Contents

1. [Overview](#1-overview)
2. [What Is a Packer](#2-what-is-a-packer)
3. [Usage](#3-usage)
4. [Build System](#4-build-system)
5. [Architecture](#5-architecture)
6. [ELF Background](#6-elf-background)
7. [Encryption Target: Segment vs. Section](#7-encryption-target-segment-vs-section)
8. [The ChaCha20 Cipher](#8-the-chacha20-cipher)
9. [Stub Injection](#9-stub-injection)
10. [Placeholder Patching](#10-placeholder-patching)
11. [The Runtime Stub (`decrypter.asm`)](#11-the-runtime-stub-decrypterasm)
12. [Error Handling](#12-error-handling)
13. [Project Structure](#13-project-structure)
14. [Testing](#14-testing)
15. [References](#15-references)

## 1. Overview

`woody_woodpacker` is an ELF64 packer. Given a 64-bit x86_64 executable, it produces a new executable, `woody`, whose executable code has been encrypted. When `woody` runs, it prints the marker `....WOODY....`, decrypts its own code in memory, then behaves exactly like the original program: same output, same exit behavior, no observable difference to the caller.

It's not a compression tool. The point is to demonstrate binary protection through encryption: parse and validate an ELF64 file, generate a cryptographically random key, encrypt the executable segment with ChaCha20, and inject a small self-decrypting stub so the encrypted code can restore and run itself at runtime, with no dependency on the original file.

Encryption is mandatory, not optional, and a weak cipher (e.g. a byte rotation) doesn't satisfy the requirements. Why ChaCha20: [Section 8](#8-the-chacha20-cipher).

## 2. What Is a Packer

A packer wraps an already-compiled executable inside another one, compressing or encrypting it, and attaches a small piece of code, the stub, that undoes that at runtime and launches the original as if nothing had happened.

Two reasons packers exist:

- **Legitimate use**: shrink the binary on disk (compression, e.g. UPX) or protect intellectual property by making static reverse engineering harder, the real code isn't visible in the file until it decrypts itself in memory at runtime.
- **Malware**: antivirus tools largely rely on matching known byte signatures. Packing the same malware with a different key each time changes its on-disk signature while its behavior stays identical, defeating static detection. This is why packers are a standard exercise in offensive security training: understanding how a binary hides itself is a prerequisite for detecting one that does.

`woody_woodpacker` builds a minimal version of this: parse and validate an ELF64 file, generate a random key, encrypt the executable code with ChaCha20, inject a stub that decrypts and runs it. No compression, no anti-debugging tricks, just the core encrypt-and-self-decrypt mechanism a real packer is built around.

## 3. Usage

After building (see [Section 4](#4-build-system)), `woody_woodpacker` takes one argument: the path to a 64-bit x86_64 ELF executable.

```
./woody_woodpacker <path-to-elf-binary>
```

On success:

- A random encryption key prints to standard output: `key_value: <hexadecimal key>`.
- A new file, `woody`, is created in the current directory. The original input file is left untouched.

`woody` runs the same way the original program would, same arguments, since the packer only replaces the entry point and doesn't touch how `argv`/`envp` are passed. It prints `....WOODY....`, decrypts itself in memory, then runs exactly as the original would:

```
$ ./woody_woodpacker sample
key_value: 07A51FF040D45D5CD

$ ./sample
Hello, World!

$ ./woody
....WOODY....
Hello, World!
```

If the input file is missing, not a valid ELF file, or not 64-bit x86_64, `woody_woodpacker` prints an error and exits with failure, without creating `woody`. Details: [Section 12](#12-error-handling).

## 4. Build System

Built with `make` and `gcc`. No manual setup beyond having `git` available: the standard library helpers come in automatically as a Git submodule ([libft](https://github.com/AingeruAlvarezSanchez/Libft)) on first build.

Available targets:

| Target          | Description                                                                                                  |
|-----------------|--------------------------------------------------------------------------------------------------------------|
| `all` (default) | Fetches the `libft` submodule if missing, compiles all sources, and links the `woody_woodpacker` executable. |
| `clean`         | Removes intermediate object files.                                                                           |
| `fclean`        | Runs `clean` and additionally removes the `woody_woodpacker` executable.                                     |
| `re`            | Removes the `libft` submodule entirely and rebuilds everything from a clean state.                           |
| `sanitize`      | Rebuilds with AddressSanitizer and LeakSanitizer enabled, for debugging memory issues.                       |

```
make        # build woody_woodpacker
make re     # full rebuild, including the libft submodule
make clean  # remove object files only
make fclean # remove object files and the final executable
```

`src/decrypter.asm` isn't part of the build. The actual runtime stub lives as a raw byte array in `inc/stub.h`. `decrypter.asm` stays in the repo as a human-readable reference: it documents the assembly, it doesn't compile into it.

## 5. Architecture

Packing happens in one pass, driven by `main()` in `src/woody_woodpacker.c`, in five stages:

1. **Validation.** Open and map the input file, check it's a well-formed ELF64 file for x86_64. Anything else gets rejected before any other work. [Section 6](#6-elf-background).

2. **Key generation.** A fresh, random ChaCha20 state, key, nonce, initial counter, from `/dev/urandom`. [Section 8](#8-the-chacha20-cipher).

3. **Encryption.** Find and encrypt the executable segment in place with that state. [Section 7](#7-encryption-target-segment-vs-section).

4. **Stub injection.** Add a small runtime stub as a new loadable segment, make it the new entry point. It carries the key, the nonce, and the encrypted segment's location. [Section 9](#9-stub-injection), [Section 10](#10-placeholder-patching).

5. **Output.** Print the key, write the modified file as `woody`. The original file is never touched.

At runtime, `woody` reverses part of this: the stub runs first, decrypts the segment in memory, hands control to the original entry point. The rest of execution looks identical to running the unpacked binary. [Section 11](#11-the-runtime-stub-decrypterasm).

## 6. ELF64 Background

### What ELF Is

ELF (Executable and Linkable Format) is Linux's file format for executables, shared libraries, and object files. It's not raw machine code: it's a structured container that tells the OS what to load, where, with what permissions, and where to start executing.

This project only handles ELF64 executables for x86_64, so this section only covers what's relevant to that.

An ELF64 file has three building blocks, in this order:

```
┌───────────────────────────┐
│   ELF Header (Ehdr)       │   fixed size, always at offset 0
├───────────────────────────┤
│   Program Header Table    │   array of Phdr entries, used at RUNTIME
├───────────────────────────┤
│   Sections / raw data     │   the actual code, data, symbols, etc.
├───────────────────────────┤
│   Section Header Table    │   array of Shdr entries, used at LINK TIME
└───────────────────────────┘
```

The two header tables describe the same bytes, for different audiences:

- **Program headers** describe the file the way the **kernel** sees it at `execve()` time: which byte ranges get mapped into memory, at which address, with which permissions (read/write/execute). This is the table `woody_woodpacker` cares about.
- **Section headers** describe the file the way a **linker or debugger** sees it: named regions like `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), `.symtab` (symbol table). The kernel ignores this table entirely when running a program, it exists for tooling, not execution.

`woody_woodpacker` only needs what the kernel loads and runs, so it works exclusively with the program header table. Section headers aren't used anywhere in this project. More on why: [Section 7](#7-encryption-target-segment-vs-section).

### The ELF Header (`Elf64_Ehdr`)

Every ELF64 file starts with a fixed-size header, `Elf64_Ehdr` in `<elf.h>`. It identifies the file as ELF, states its target architecture, and points to the two header tables above. Only the fields this project reads are listed here:

| Field       | Size     | Purpose                                                          |
|-------------|----------|--------------------------------------------------------------------|
| `e_ident`   | 16 bytes | Magic number and file class/encoding identification (see below). |
| `e_machine` | 2 bytes  | Target CPU architecture, e.g. `EM_X86_64`.                       |
| `e_entry`   | 8 bytes  | Virtual address where execution starts once the file is loaded.  |
| `e_phoff`   | 8 bytes  | File offset where the program header table begins.               |
| `e_phnum`   | 2 bytes  | Number of entries in the program header table.                   |

#### `e_ident`: identifying the file

The first 16 bytes of any ELF file are an identification block, not code or data. The first 4 bytes are the magic number, always the same for every ELF file:

```
offset:   0    1    2    3
bytes:  0x7f  'E'  'L'  'F'
```

`woody_woodpacker` checks these 4 bytes first (`ELFMAG`/`SELFMAG` in `<elf.h>`). If they don't match, the file isn't ELF at all, and processing stops with the `Not an ELF file` error.

One byte further into `e_ident`, at index `EI_CLASS`, a single byte states whether the file is 32-bit or 64-bit:

| Value            | Meaning    |
|------------------|------------|
| `ELFCLASS32` (1) | 32-bit ELF |
| `ELFCLASS64` (2) | 64-bit ELF |

`woody_woodpacker` only accepts `ELFCLASS64`. Combined with `e_machine` being `EM_X86_64`, this check produces the `File architecture not suported. x86_64 only` error for anything else (a 32-bit binary, an ARM binary, etc.).

#### `e_entry`: where execution begins

`e_entry` is a **virtual address**, not a file offset (see the distinction below): the address the CPU jumps to first once the kernel finishes loading the file. For a normal, unpacked program, this points at the C runtime startup code that eventually calls `main()`.

Packing means changing this one field to point at the injected stub instead. The original value isn't discarded, the stub needs it to jump back into the real program after decrypting. [Section 9](#9-stub-injection).

#### `e_phoff` / `e_phnum`: locating the program header table

`e_phoff` is the file offset where the program header table begins, `e_phnum` is how many entries it has. Together they let `woody_woodpacker` walk every program header without knowing its size in advance:

```
program_header[i] = elf_file_bytes + e_phoff + i * sizeof(Elf64_Phdr)
```

### The Program Header Table (`Elf64_Phdr`)

Each entry is one `Elf64_Phdr` struct, describing one **segment**: a contiguous byte range the kernel treats as a single unit when loading the program. Fields this project reads or modifies:

| Field      | Purpose                                                                                          |
|------------|--------------------------------------------------------------------------------------------------|
| `p_type`   | What kind of segment this is (see below).                                                        |
| `p_flags`  | Permissions to map this segment with: readable, writable, executable.                            |
| `p_offset` | Where this segment's bytes start **in the file**.                                                |
| `p_vaddr`  | Where this segment should be mapped **in memory** (virtual address).                             |
| `p_filesz` | How many bytes of this segment exist in the file.                                                |
| `p_memsz`  | How many bytes this segment should occupy in memory (can be larger than `p_filesz`; see below).  |
| `p_align`  | Required alignment, almost always the page size, `0x1000` (4096 bytes) on x86_64.                |

#### `p_type`: segment kinds this project cares about

- **`PT_LOAD`**: a segment that must be mapped into memory when the program starts. A typical executable has at least two: one read+execute segment holding code, one read+write segment holding initialized/uninitialized data. `woody_woodpacker` looks for the `PT_LOAD` segment that's also executable (`p_flags & PF_X`), that's the region it encrypts. [Section 7](#7-encryption-target-segment-vs-section).

- **`PT_NOTE`**: a segment that normally holds auxiliary metadata (build IDs, ABI tags), not required to run the program. `woody_woodpacker` repurposes it: since its contents are disposable, the entry gets overwritten into a brand-new `PT_LOAD` segment carrying the injected stub, instead of appending a new entry (which would require relocating everything after it). [Section 9](#9-stub-injection). A `PT_NOTE` segment must be present in the input file for this to work; see [Section 12](#12-error-handling) for what happens when it's missing.

#### `p_flags`: segment permissions

A bitmask built from three flags, combined with bitwise OR:

| Flag   | Meaning                |
|--------|------------------------|
| `PF_R` | Segment is readable.   |
| `PF_W` | Segment is writable.   |
| `PF_X` | Segment is executable. |

`PF_R | PF_X` (readable and executable, not writable) is the typical permission set for a program's code segment. `woody_woodpacker` needs the encrypted segment to also be writable at runtime, so the stub can overwrite encrypted bytes with decrypted ones in place. That's why the injected stub's own segment is mapped `PF_R | PF_W | PF_X`, and why the runtime stub calls `mprotect` before decrypting ([Section 11](#11-the-runtime-stub-decrypterasm)).

#### File offset vs. virtual address

`p_offset` and `p_vaddr` describe the *same* bytes from two different angles, easy to confuse:

- `p_offset`: where to find those bytes **inside the file on disk**.
- `p_vaddr`: where the kernel places those bytes **in the process's virtual memory** once loaded.

These are different numbers, a segment might start at file offset `0x2000` but map at virtual address `0x401000`. Converting between the two, an address the CPU sees at runtime versus a position to write to while editing the file on disk, matters for how the stub itself gets located. It also matters for how the stub later finds the encrypted segment at runtime, relative to its own position (`_start`) rather than an absolute address only valid for one file.

#### `p_filesz` vs. `p_memsz`

`p_filesz` is how many bytes of a segment exist in the file; `p_memsz` is how many bytes it should occupy once loaded into memory. When `p_memsz` is larger, the kernel zero-fills the extra space, this is how uninitialized global variables (`.bss`) get memory without taking up file space. For the stub segment injected by `woody_woodpacker`, both are set to the stub's exact size: it's fully present in the file, no extra zero-filled space needed.

#### `p_align`

Segments must start at an address that's a multiple of `p_align`, the page size on x86_64 Linux, `0x1000` (4096) bytes. The kernel manages memory in fixed-size pages, and permissions (`PF_R`/`PF_W`/`PF_X`) are only ever set per page, not per byte. That's why placing a new segment (the injected stub) requires rounding its virtual address up to the next page boundary, rather than appending it right after the previous segment ends.

## 7. Encryption Target: Segment vs. Section

An earlier version of this project encrypted an ELF file by walking its **section header table** and encrypting every section marked executable (`SHF_EXECINSTR`), typically `.text`, `.plt`, and a handful of others. That required tracking a list of regions, one address and one size per matching section, in a small table carried alongside the file and consulted again at decryption time.

The current version encrypts differently: it locates the single `PT_LOAD` **segment** that's also executable (`p_flags & PF_X`, see [Section 6](#6-elf64-background)) and encrypts that one contiguous region as a whole. No table of regions needed.

This works because of how the linker lays out a normal executable: all of a program's executable sections are already placed contiguously and loaded by the kernel as a single executable `PT_LOAD` segment. The segment-based approach just reads that information from one header entry instead of scanning a variable-length list of named sections.

Two consequences for the design:

- **Section headers become unnecessary for packing.** The section header table only exists for linking and debugging tools, the kernel never reads it, and a stripped executable may not even have one. Depending on it to locate the code to encrypt would make the packer fragile against binaries built without that information. The program header table, in contrast, is required for the kernel to run the file at all.

- **No region table has to be carried in the packed file.** One address and one size get patched directly into the injected stub as two fixed placeholders (see [Section 10](#10-placeholder-patching)), instead of being appended to the output file as a separate data table the stub would need to loop over at runtime. That removes an entire loop, and a whole class of bugs around table layout, from both the packer and the runtime stub.

## 8. The ChaCha20 Cipher

### Why Not Encrypt Byte by Byte

A naive cipher transforms each byte of the input using only that byte and the key, for instance, adding 1 to every byte:

```
plaintext:   H    I
             0x48 0x49
+1:          0x49 0x4a
ciphertext:  I    J
```

Trivially predictable: each byte is transformed in isolation, with no dependency on its position or the rest of the message, so patterns in the plaintext leak directly into the ciphertext. This is also why the project's subject explicitly disqualifies a plain byte rotation as an acceptable algorithm.

ChaCha20 avoids this by never operating on the plaintext directly. It generates a **keystream**, a block of bytes statistically indistinguishable from random noise, derived only from a key, a nonce, and a block counter (none of which depend on the plaintext), and combines that keystream with the plaintext using XOR, one byte at a time.

### Keystream and XOR

ChaCha20 always produces its keystream in fixed 64-byte blocks. If the data to encrypt is shorter than 64 bytes, only the needed prefix is used, the rest discarded. For example, encrypting the 2-byte string `"HI"` (`H` = `0x48`, `I` = `0x49`) against the first two bytes of a generated keystream:

|                                        | byte 1               | byte 2               |
|----------------------------------------|----------------------|----------------------|
| plaintext (`"HI"`)                     | `0x48`               | `0x49`               |
| keystream (first 2 bytes of the block) | `0x3f`               | `0x91`               |
| XOR                                    | `0x48 ^ 0x3f = 0x77` | `0x49 ^ 0x91 = 0xd8` |
| ciphertext                             | `0x77`               | `0xd8`               |

Decryption regenerates the exact same keystream (same key, nonce, counter) and XORs it against the ciphertext again, XOR is its own inverse (`(a ^ b) ^ b = a`), so encryption and decryption are the same operation. That's also why the runtime stub doesn't need a separate decryption routine: it runs the same block generation and XOR logic the packer used to encrypt ([Section 11](#11-the-runtime-stub-decrypterasm)).

None of the cryptographic strength comes from the XOR step itself, a trivial, well-known operation, it comes entirely from how unpredictable the keystream is. That unpredictability is produced by mixing a 64-byte input block, the **state**, through many rounds of simple arithmetic. The state is 16 words of 32 bits each (16 × 4 = 64 bytes), conventionally drawn as a 4×4 matrix:

```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│  states[0]  │  states[1]  │  states[2]  │  states[3]  │  ← fixed constant
├─────────────┼─────────────┼─────────────┼─────────────┤
│  states[4]  │  states[5]  │  states[6]  │  states[7]  │  ← key
├─────────────┼─────────────┼─────────────┼─────────────┤
│  states[8]  │  states[9]  │  states[10] │  states[11] │  ← key
├─────────────┼─────────────┼─────────────┼─────────────┤
│  states[12] │  states[13] │  states[14] │  states[15] │  ← counter + nonce
└─────────────┴─────────────┴─────────────┴─────────────┘
```

### Composition of the State

| Indices    | Field         | Size               | Source                                                     |
|------------|---------------|--------------------|-------------------------------------------------------------|
| `[0..3]`   | constant      | 16 bytes           | fixed, identical for every ChaCha20 stream                 |
| `[4..11]`  | key           | 32 bytes (256 bit) | `/dev/urandom`                                             |
| `[12]`     | block counter | 4 bytes            | starts at `1`, incremented once per 64-byte block produced |
| `[13..15]` | nonce         | 12 bytes (96 bit)  | `/dev/urandom`                                             |

All 16 words are required to reproduce a given keystream correctly. If any single word is missing or different, the resulting keystream (and therefore the XOR output) changes, and decryption fails silently rather than with an explicit error.

- **Constant (`[0..3]`)**: 16 fixed bytes defined by the ChaCha20 specification, the ASCII string `"expand 32-byte k"` split into four 4-byte words. Never changes between uses of the cipher.
- **Key (`[4..11]`)**: 32 random bytes read from `/dev/urandom`. The secret the algorithm's name refers to, though on its own it can't reproduce a keystream without the constant, counter, and nonce alongside it.
- **Block counter (`[12]`)**: identifies which 64-byte block of the stream is currently being generated. Encrypting 200 bytes of data requires 4 blocks (256 bytes of keystream, with the last 56 discarded), so the counter takes the values `1, 2, 3, 4` across those blocks. A different counter value produces a different keystream even with an identical key and nonce, which is what lets the cipher safely produce more than 64 bytes of keystream from a single key.
- **Nonce (`[13..15]`)**: "number used once", 12 random bytes. Ensures reusing the same key for a different message doesn't reuse the same keystream.

#### Worked Example

```
constant (fixed):     61707865 3320646e 79622d32 6b206574

key (random):         42a9b0c1 f13e88aa 0091cd77 55019bdd
                      aa77f102 c3ee4401 8bc0a999 f0112233

counter:              00000001

nonce (random):       0a0b0c0d 1e2f3041 52637485
```

Combined, the full state (`states[0]` through `states[15]`):

```
61707865 3320646e 79622d32 6b206574
42a9b0c1 f13e88aa 0091cd77 55019bdd
aa77f102 c3ee4401 8bc0a999 f0112233
00000001 0a0b0c0d 1e2f3041 52637485
```

These 16 words (64 bytes) are the input. They pass through 20 rounds of mixing (quarter rounds), after which the resulting words form the keystream.

### Quarter Rounds

#### What a Quarter Round Does

A quarter round takes 4 of the state's 16 words (a "quarter" of the total) and mixes them together using three simple operations, addition, XOR, and bit rotation, applied four times in a fixed order. Calling the four words `a`, `b`, `c`, `d`:

| Step | Operation                                        |
|------|--------------------------------------------------|
| 1    | `a += b` ; `d ^= a` ; rotate `d` left by 16 bits |
| 2    | `c += d` ; `b ^= c` ; rotate `b` left by 12 bits |
| 3    | `a += b` ; `d ^= a` ; rotate `d` left by 8 bits  |
| 4    | `c += d` ; `b ^= c` ; rotate `b` left by 7 bits  |

A left bit rotation shifts bits out of the high end and reinserts them at the low end, rather than discarding them as a plain shift would. Rotating an 8-bit value left by 2 bits, for example:

```
before:  1101 0010
              ↑↑ these 2 bits...
after:   0100 1011
                 ↑↑ ...reappear at the low end
```

#### Why This Mixing Is Done

The goal is an output that looks chaotic while staying fully deterministic: the same key, nonce, and counter always produce the same keystream, yet flipping a single bit of the key changes roughly half the output bits, with no discernible pattern. Repeated addition, XOR, and rotation make every word end up influenced by every other word, which is what makes it computationally infeasible to recover the key from an observed keystream.

#### Round Count and Word Groupings

ChaCha20 performs **20 rounds** in total, organized as 10 iterations of 2 rounds each:

- One **column round**, applying the quarter round once per vertical column of the 4×4 matrix, 4 quarter-round applications.
- One **diagonal round**, applying it once per diagonal (with wrap-around), another 4 applications.

Each iteration performs `4 + 4 = 8` quarter-round applications. Repeating that 10 times covers all 20 rounds, `10 × 8 = 80` quarter-round applications in total.

**Column round**, groups `(a, b, c, d)` taken from each column of:

```
 0  1  2  3
 4  5  6  7
 8  9 10 11
12 13 14 15
```

groups: `(0,4,8,12)` `(1,5,9,13)` `(2,6,10,14)` `(3,7,11,15)`

**Diagonal round**, same indices, taken diagonally with wrap-around:

```
 A  B  C  D
 D  A  B  C
 C  D  A  B
 B  C  D  A
```

groups: `(0,5,10,15)` `(1,6,11,12)` `(2,7,8,13)` `(3,4,9,14)`

Column and diagonal rounds alternate, ten times each, for 20 rounds total. After the last round, the 16 mixed words are added, word by word, to the *original* (pre-mixing) state one final time, that addition is what produces the finished 64-byte keystream block.

### How This Maps to the Project's Source

`src/chacha20.c` implements the algorithm described above:

- `prepare_chacha20_stream` builds the initial state: `states[0..3]` are the fixed constants (`CHACHA20_C0`..`CHACHA20_C3`, defined in `inc/woody_woodpacker.h`), `states[4..11]` are 32 bytes read from `/dev/urandom`, `states[12]` is set to `1`, and `states[13..15]` are 12 further random bytes.
- `chacha20_quarter_round` implements the four-step operation from [Quarter Rounds](#quarter-rounds) on four `__uint32_t` pointers.
- `chacha20_block` runs the 10-iteration loop (8 quarter-round calls each, alternating column and diagonal groupings), performs the final add-back against the original state, and serializes the 16 resulting words into a 64-byte `keystream` buffer, least-significant byte first, matching the byte order the spec defines for a block's output.
- `encrypt_block` calls `chacha20_block` once per 64-byte chunk of the target data, incrementing the block counter (`states[12]`) between calls, and XORs each chunk with the freshly generated keystream. Encryption and decryption are therefore the exact same function here, applied to plaintext or to ciphertext.
- `chacha20_encrypt` locates the executable segment to protect ([Section 7](#7-encryption-target-segment-vs-section)) and calls `encrypt_block` on it.

The `key_value` printed to standard output isn't just the 32-byte key: `main()` prints all 16 state words in sequence, constant, key, nonce, counter, as one continuous hex string. The counter word prints as its fixed starting value, `1`, rather than the already-advanced `elf.states[12]`, since decrypting the first block at runtime needs the counter to start at `1` again.

## 9. Stub Injection

Injecting the runtime stub means adding a new executable region to the file, and pointing the entry point at it, without changing anything the original binary needs to keep running correctly. Done by `inject_stub` in `src/stub.c`, in four steps.

### Changing the `PT_NOTE` Segment

Appending a brand-new entry to the program header table would push every later byte further into the file, invalidating every other segment's `p_offset`. To avoid that, `woody_woodpacker` reuses an existing entry instead: it scans for a `PT_NOTE` segment (see [Section 6](#6-elf64-background)) and overwrites that entry in place, turning it into a new `PT_LOAD` segment for the stub. No `PT_NOTE` segment means no safe slot to repurpose, and the process aborts ([Section 12](#12-error-handling)).

### Placing the Stub in Memory

While scanning for `PT_NOTE`, the same pass tracks the highest virtual address used by any existing `PT_LOAD` segment (`p_vaddr + p_memsz`). The new stub segment goes right after that point, rounded up to the next page boundary, so it can't overlap any segment the original program already relies on.

ELF also requires a segment's file offset and virtual address to agree on the page size (`p_vaddr % p_align == p_offset % p_align`), so the computed address gets further adjusted by the low 12 bits of the chosen file offset to satisfy that constraint.

### Repurposed Segment Fields

The repurposed entry is rewritten with the following fields:

| Field                 | New value              | Reason                                                                                 |
|-----------------------|-------------------------|-----------------------------------------------------------------------------------------|
| `p_type`              | `PT_LOAD`              | The segment must now be mapped into memory at load time.                                |
| `p_flags`             | `PF_R \| PF_W \| PF_X` | The stub needs to execute and write decrypted bytes back over the encrypted ones.        |
| `p_offset`            | `elf->offset`          | The end of the original file: where the stub's bytes get appended when `woody` is written out (`create_woody_executable`). |
| `p_filesz`, `p_memsz` | `stub_len`             | The stub is fully present in the file, no extra zero-filled space needed.               |
| `p_vaddr`             | as computed above      | Where the stub is mapped at runtime.                                                    |
| `p_align`             | `0x1000`               | Required page alignment.                                                                |

`header->e_entry` is then overwritten with this new `p_vaddr`, so the stub, not the program's original startup code, is what the kernel jumps to first.

### Making the Stub Position-Independent

The stub can't rely on any address being fixed in advance, since where it ends up in the file (and in memory) depends on the input binary being packed. Rather than patch in absolute addresses, `inject_stub` computes two values *relative to the stub's own new `p_vaddr`*:

- `entry_cpy - pt_note->p_vaddr`: how far the *original* entry point sits from the stub's starting address. Lets the stub jump back to the real program once decryption is done, by adding this offset to its own runtime address ([Section 11](#11-the-runtime-stub-decrypterasm)).
- `elf->program_addr -= pt_note->p_vaddr`: the same treatment applied to the encrypted segment's address ([Section 7](#7-encryption-target-segment-vs-section)), so the stub can locate the bytes it needs to decrypt.

Both values, together with the encrypted segment's size and the ChaCha20 key and nonce, get written into the stub's own bytes by `replace_asm_placeholder`, see [Section 10](#10-placeholder-patching).

## 10. Placeholder Patching

The stub's machine code is fixed ahead of time in `inc/stub.h`. It can't know, at assembly time, the entry-point offset, the encrypted segment's address and size, or the ChaCha20 key and nonce, since all of those depend on the specific file being packed. `woody_woodpacker` solves this by embedding recognizable values in the stub's data at assembly time, then overwriting them with the real values once they're known.

### Sentinel Constants

`src/decrypter.asm` reserves one 8-byte slot per runtime value, each initialized to a distinctive placeholder constant unlikely to occur by coincidence in real program data:

```
oe:      dq 0xDEADC0DEDEADC0DE   ; original entry-point offset
ph_addr: dq 0xC0FFEE00C0FFEE00   ; encrypted segment address
ph_size: dq 0xDEADBEEFDEADBEEF   ; encrypted segment size
seed:    ...                     ; key words filled with 0xCAFEBABE
                                 ; nonce words filled with 0xFEEDFACE
```

These same constants are defined in `inc/woody_woodpacker.h` (`ENTRY_PLACEHOLDER`, `PHADDR_PLACEHOLDER`, `PHSIZE_PLACEHOLDER`, `KEY_PLACEHOLDER`, `NONCE_PLACEHOLDER`), so the C code and the assembly data agree on exactly which bytes to look for.

### Scanning and Replacing

`replace_asm_placeholder`, in `src/stub.c`, drives the process with a small lookup table:

```c
typedef struct s_placeholder {
    uint64_t placeholder;
    const uint32_t *src;
    size_t words;
} t_placeholder;
```

Each row pairs one sentinel with the real data that replaces it, and how many 4-byte words to copy, most values are 2 words, except the key (32 bytes / 8 words) and the nonce (12 bytes / 3 words):

| Placeholder          | Replaced with                                           | Words |
|-----------------------|-----------------------------------------------------------|-------|
| `ENTRY_PLACEHOLDER`  | entry-point offset (see [Section 9](#9-stub-injection)) | 2     |
| `PHADDR_PLACEHOLDER` | encrypted segment address (`elf->program_addr`)         | 2     |
| `PHSIZE_PLACEHOLDER` | encrypted segment size (`elf->program_size`)            | 2     |
| `KEY_PLACEHOLDER`    | ChaCha20 key (`elf->states[4..11]`)                     | 8     |
| `NONCE_PLACEHOLDER`  | ChaCha20 nonce (`elf->states[13..15]`)                  | 3     |

The function walks every byte offset of the stub, reinterpreting each 8-byte window as a `uint64_t` and comparing it against all five sentinels. On a match, `fill_placeholder` overwrites that spot with the real value, and the scan skips past the bytes it just wrote, both to avoid re-matching, and because the next real placeholder doesn't need a byte-by-byte search from where the previous one started.

If the scan doesn't find all five sentinels exactly once, injection fails with the `ENOPHOLDER` error ([Section 12](#12-error-handling)) rather than shipping a `woody` file with stale placeholder bytes still in it.

### Why Sentinel Values Instead of Fixed Offsets

An alternative design would hardcode the byte offset of each value inside the compiled stub directly. That's fragile: any change to `src/decrypter.asm` that shifts surrounding code or data, even one unrelated to these values, would silently invalidate every hardcoded offset. Searching for a unique constant instead keeps the patching logic working correctly as long as the constant stays somewhere in `.data`, regardless of where the assembler places it.

## 11. The Runtime Stub (`decrypter.asm`)

Once `woody` is launched, the injected stub is the first code to run ([Section 9](#9-stub-injection)). Written in x86_64 assembly for direct control over registers and syscalls, it has four jobs: announce that the binary is packed, temporarily make the encrypted segment writable, decrypt it in place, and hand control back to the original program.

### Announcing the Packed Binary

`_start` first saves the four general-purpose registers it's about to use (`rax`, `rdi`, `rsi`, `rdx`), then issues a `write` syscall printing the `....WOODY....` marker. Saving these registers matters because once the stub finishes, the original program's startup code must resume exactly as the kernel would have left it, it shouldn't be able to tell a stub ran before it.

### Locating the Encrypted Segment at Runtime

The stub has no fixed address to work from: the same bytes need to work no matter where in memory the kernel loads them. `_start` reads its own runtime address with `lea r14, [rel _start]`, and adds the segment offset patched in by [Section 10](#10-placeholder-patching) (`ph_addr`) to get the current address of the encrypted segment, the same computation `inject_stub` anticipated when it stored that offset relative to the stub's `p_vaddr`.

### Making the Segment Writable

Decryption happens in place: the stub overwrites the encrypted bytes with decrypted ones, inside the same memory the kernel already mapped read+execute only. Before writing anything, `decrypt` calls `mprotect` on that region with `PROT_READ | PROT_WRITE | PROT_EXEC`. Since `mprotect` only operates on whole pages, the target address rounds down to its containing page, and the requested size extends by however far into that page the address originally was, otherwise a segment not starting exactly on a page boundary could leave its first few bytes unprotected.

### Decrypting the Segment

`chacha20` reproduces, in assembly, the same block cipher described in [Section 8](#8-the-chacha20-cipher):

- `.block_loop` copies the untouched `seed` (the key/nonce/counter state patched in by [Section 10](#10-placeholder-patching)) into a working buffer, `rkeystream`, mirroring `chacha20_block`'s local `working_state` copy in C, the original seed has to stay available for the final add-back step and for the next block.
- `.round_loop` / `.qround_loop` run the 10 iterations of 8 quarter-round applications each (see [Round Count and Word Groupings](#round-count-and-word-groupings)), reading which four words to mix from a `qround_table` encoding the same column/diagonal groupings used in `src/chacha20.c`. `qround` translates the four-step quarter round into `add`, `xor`, `rol`.
- `.addback_loop` adds the original `seed` words back into the mixed block, producing the finished 64-byte keystream.
- `.xor_loop` XORs that keystream against up to 64 bytes of the encrypted segment directly in memory, decrypting them in place; if fewer than 64 bytes remain, only that many are used, exactly as `encrypt_block` does in C.
- The block counter (part of `seed`) increments, and `.block_loop` repeats until the entire segment (`ph_size` bytes) has been processed.

### Returning to the Original Program

Once decryption completes, the saved registers are restored, and the stub computes the real program's entry point the same way it located the encrypted segment: its own runtime address, plus the entry-point offset patched in by [Section 10](#10-placeholder-patching) (`oe`). Jumping there hands control to the original program's startup code, now fully decrypted in memory, every register left exactly as the kernel originally set it up, so the rest of execution looks like running the unpacked binary directly.

## 12. Error Handling

Every operation in `woody_woodpacker` is checked, and every failure path converges on a single helper, `error()` in `src/woody_woodpacker.c`:

```c
__uint8_t error(char *msg) {
    ft_putendl_fd(msg, STDOUT_FILENO);
    return EXIT_FAILURE;
}
```

It writes a descriptive message to standard output and returns `EXIT_FAILURE`, which every calling function propagates upward immediately, without attempting further work. `create_woody_executable`, the function that opens `woody` for writing, is only reached once validation, encryption, and stub injection have all already succeeded, so no `woody` file is ever created, partially or otherwise, when packing fails for any reason.

### Error Conditions

| Cause                                                                                | Message                                                                      | Where                     |
|--------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|---------------------------|
| Wrong number of command-line arguments                                               | `strerror(EINVAL)`                                                           | `main`                    |
| Input file cannot be opened, `lseek`'d, or `mmap`'d                                  | `strerror(errno)`                                                            | `validate_elf_file`       |
| File is smaller than an ELF header, or its magic bytes don't match                   | `Not an ELF file`                                                            | `validate_elf_file`       |
| File is not `ELFCLASS64` / `EM_X86_64`                                               | `File architecture not suported. x86_64 only`                                | `validate_elf_file`       |
| `/dev/urandom` cannot be opened or read                                              | `strerror(errno)`                                                            | `prepare_chacha20_stream` |
| No `PT_NOTE` segment to repurpose (see [Section 9](#9-stub-injection))               | `ELF does not contain a PT_NOTE symbol. Aborting`                            | `inject_stub`             |
| Not all five stub placeholders were found (see [Section 10](#10-placeholder-patching)) | `the stub doesn't contain one or more expected placeholder values. Aborting` | `inject_stub`             |
| `woody` cannot be opened or written                                                  | `strerror(errno)`                                                            | `create_woody_executable` |
| The mapped input file cannot be `munmap`'d                                           | `strerror(errno)`                                                            | `main`                    |

### Scope

This covers `woody_woodpacker` itself, at packing time. The subject's requirement that "the encrypted program must never crash" targets the *output* of that process, `woody`: since packing only ever completes successfully on a file that already passed every check above, the runtime stub ([Section 11](#11-the-runtime-stub-decrypterasm)) can assume it's always operating on a well-formed segment, entry point, and key/nonce pair, and doesn't need to re-validate them itself.

## 13. Project Structure

```
woody-woodpacker/
├── src/
│   ├── woody_woodpacker.c   entry point: validation, orchestration, output
│   ├── chacha20.c           ChaCha20 state, block cipher, segment encryption
│   ├── stub.c               stub injection and placeholder patching
│   └── decrypter.asm        human-readable reference for the runtime stub
├── inc/
│   ├── woody_woodpacker.h   shared types, constants, and error messages
│   └── stub.h               generated stub byte array (see Section 4)
├── docs/
│   ├── en.subject.pdf       project specification
│   └── resources/           sample input binaries used for manual testing
├── libft/                   C helpers, pulled in as a Git submodule
├── Dockerfile
├── docker-compose.yaml
├── LICENSE
├── makefile
└── README.md
```

| Component                | Responsibility                                                                                             |
|----------------------------|---------------------------------------------------------------------------------------------------------------|
| `src/woody_woodpacker.c` | `main()` and the pipeline from [Section 5](#5-architecture): validates the input, drives key generation, encryption, and stub injection in order, prints `key_value`, writes `woody`. |
| `src/chacha20.c`         | Building the initial state, the quarter round and block functions, locating/encrypting the executable segment ([Section 8](#8-the-chacha20-cipher)). |
| `src/stub.c`             | Repurposing the `PT_NOTE` segment for the stub and patching its placeholder values ([Section 9](#9-stub-injection), [Section 10](#10-placeholder-patching)). |
| `src/decrypter.asm`      | Documents, in readable assembly, the logic already compiled into `inc/stub.h` ([Section 11](#11-the-runtime-stub-decrypterasm)); not compiled by `make`. |
| `inc/woody_woodpacker.h` | The `t_elf` struct, constants shared across `.c` files (placeholder values, error messages, ChaCha20 constants), function prototypes. |
| `inc/stub.h`             | The actual stub bytes linked into `woody_woodpacker`, pre-generated from `src/decrypter.asm` ([Section 4](#4-build-system)). |
| `docs/en.subject.pdf`    | The original project specification this README's requirements are drawn from.                                 |
| `docs/resources/`        | `sample.c` and a compiled `sample` binary for manual testing, `mini.c` for the walkthrough in [Section 14](#14-testing), plus a reference packed `woody` binary shipped with the specification. |
| `libft/`                 | A small vendored C standard-library helper set, fetched automatically as a Git submodule ([Section 4](#4-build-system)). |

## 14. Testing

No automated test suite. Verified by building a small executable, packing it, and confirming the packed result behaves identically to the original, the same way the project's subject itself describes checking it.

### `docs/resources/mini.c`

A minimal C program that also accepts an optional command-line argument, so packing has to preserve argument handling too, not just output:

```c
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc > 1)
        printf("mini: hello, %s!\n", argv[1]);
    else
        printf("mini: hello, world!\n");
    return 0;
}
```

### Building and Packing It

```
$ gcc -o docs/resources/mini docs/resources/mini.c
$ make

$ ./docs/resources/mini
mini: hello, world!
$ ./docs/resources/mini Woody
mini: hello, Woody!

$ ./woody_woodpacker docs/resources/mini
key_value: 617078653320646e79622d326b206574cd33c1b3fbb7450ff92069f8ea042cf636671ee5a070bdd633fdece279fbbb7e0000000100bd34b87d9f3e52630c4e31
```

`woody` is now a packed copy of `mini`, encrypted with the key printed above.

### Verifying Identical Behavior

```
$ ./woody
....WOODY....
mini: hello, world!

$ ./woody Woody
....WOODY....
mini: hello, Woody!
```

Both invocations print the `....WOODY....` marker, then exactly what `mini` would have printed for the same arguments, including the argument case, confirming `argv` reaches the original program unmodified. Both exit with status `0`, matching the original program's exit behavior.

This same procedure, compile a small real program, run `woody_woodpacker` on it, compare output and exit status against the original, is how any other candidate input can be checked, including the bundled `docs/resources/sample.c` and the reference `docs/resources/woody` binary shipped with the specification.

## 15. References

- **[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)**, "ChaCha20 and Poly1305 for IETF Protocols". Defines the ChaCha20 state layout, quarter round, and block function this project implements, in C (`src/chacha20.c`) and assembly (`src/decrypter.asm`). [Section 8](#8-the-chacha20-cipher).
- **`docs/en.subject.pdf`**. The project's own specification, source of every mandatory requirement in this document, including the exact error message wording in [Section 12](#12-error-handling).
- **`elf(5)`** man page, and the ELF64 struct definitions in `<elf.h>`. Reference used for `Elf64_Ehdr` and `Elf64_Phdr` ([Section 6](#6-elf64-background)).
- **[ELF Object File Format](https://gabi.xinuos.com/elf.pdf)**. The full ELF specification, including the program and section header formats summarized in [Section 6](#6-elf64-background).
- **`mprotect(2)`** and **`mmap(2)`** man pages. Cover the page-aligned memory permission changes this project relies on, both when mapping the input file for editing (`validate_elf_file`) and when the runtime stub makes the encrypted segment writable ([Section 11](#11-the-runtime-stub-decrypterasm)).
- **[libft](https://github.com/AingeruAlvarezSanchez/Libft)**. The vendored C standard-library helper set this project builds on ([Section 4](#4-build-system), [Section 13](#13-project-structure)).
- **[OliveStem (@olivestemlearning) Youtube Channel](https://www.youtube.com/@olivestemlearning)** (YouTube). x86/x86_64 assembly language background used while writing and reviewing `src/decrypter.asm` ([Section 11](#11-the-runtime-stub-decrypterasm)).
