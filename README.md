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
11. [The Runtime Stub (`stub.S`)](#11-the-runtime-stub-stubs)
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
- A new file, `woody`, is created in the current directory, marked executable (`0755`). The original input file is left untouched.

`woody` runs the same way the original program would, same arguments, since the packer only replaces the entry point and doesn't touch how `argv`/`envp` are passed. It prints `....WOODY....`, decrypts itself in memory, then runs exactly as the original would:

```
$ ./woody_woodpacker sample
key_value: 07a51ff040d45d5cd91b3e2a6c0f9a71cd33c1b3fbb7450ff92069f8ea042cf

$ ./sample
Hello, World!

$ ./woody
....WOODY....
Hello, World!
```

If the input file is missing, not a valid ELF file, not 64-bit x86_64, has a malformed program header table, or its entry point already sits inside a dynamic-linking segment (already packed, or PIE with the entry outside plain code), `woody_woodpacker` prints an error and exits with failure, without creating `woody`. Details: [Section 12](#12-error-handling).

## 4. Build System

Built with `make` and `gcc`. No manual setup beyond having `git` available: the standard library helpers come in automatically as a Git submodule ([libft](https://github.com/AingeruAlvarezSanchez/Libft)) on first build.

Available targets:

| Target          | Description                                                                                                         |
|-----------------|---------------------------------------------------------------------------------------------------------------------|
| `all` (default) | Fetches the `libft` submodule if missing, compiles all sources and the assembly stub, and links `woody_woodpacker`. |
| `clean`         | Removes intermediate object files.                                                                                  |
| `fclean`        | Runs `clean` and additionally removes the `woody_woodpacker` and `woody` executables.                               |
| `re`            | Runs `fclean` then `all`, a full rebuild.                                                                           |
| `debug`         | Rebuilds with debug symbols (`-g`).                                                                                 |
| `sanitize`      | Rebuilds with AddressSanitizer and LeakSanitizer enabled, for debugging memory issues.                              |

```
make        # build woody_woodpacker
make re     # full rebuild
make clean  # remove object files only
make fclean # remove object files and both executables
```

`src/stub.S` is assembled directly into `obj/stub_asm.o` and linked into `woody_woodpacker` alongside the rest of the sources. It's the actual runtime stub, not a reference kept separate from the build.

Its compiled bytes get copied out of the binary at runtime, through the `woody_stub_start`/`woody_stub_end` symbols (see [Section 9](#9-stub-injection)).

## 5. Architecture

Packing happens in one pass, driven by `main()` in `src/woody_woodpacker.c`, in five stages:

1. **Validation.** Open and map the input file, check it's a well-formed ELF64 file for x86_64 with a program header table that fits inside it. Anything else gets rejected before any other work. [Section 6](#6-elf-background).

2. **Target segment lookup.** Find the `PT_LOAD` segment containing the entry point, and reject the file if a `PT_DYNAMIC` segment overlaps it. [Section 7](#7-encryption-target-segment-vs-section).

3. **Key generation and encryption.** A fresh, random ChaCha20 state, key, nonce, initial counter, from `/dev/urandom`, used to encrypt that segment in place. [Section 8](#8-the-chacha20-cipher).

4. **Stub injection.** Add the compiled runtime stub as a new loadable segment, make it the new entry point. The keystream needed to reverse the encryption is precomputed here, at pack time, and appended to the stub as raw data. [Section 9](#9-stub-injection), [Section 10](#10-placeholder-patching).

5. **Output.** Print the key, write the modified file as `woody`. The original file is never touched.

At runtime, `woody` reverses part of this: the stub runs first, XORs the segment back to plaintext using the keystream carried inside itself, hands control to the original entry point. The rest of execution looks identical to running the unpacked binary. [Section 11](#11-the-runtime-stub-stubs).

## 6. ELF Background

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

Every ELF64 file starts with a fixed-size header, `Elf64_Ehdr` in `<elf.h>`. It identifies the file as ELF, states its target architecture, and points to the program header table. Only the fields this project reads are listed here:

| Field         | Size     | Purpose                                                                                                       |
|---------------|----------|---------------------------------------------------------------------------------------------------------------|
| `e_ident`     | 16 bytes | Magic number and file class/encoding identification (see below).                                              |
| `e_machine`   | 2 bytes  | Target CPU architecture, e.g. `EM_X86_64`.                                                                    |
| `e_entry`     | 8 bytes  | Virtual address where execution starts once the file is loaded, overwritten to point at the stub once packed. |
| `e_phoff`     | 8 bytes  | File offset where the program header table begins.                                                            |
| `e_phnum`     | 2 bytes  | Number of entries in the program header table.                                                                |
| `e_phentsize` | 2 bytes  | Size of one program header entry, validated against `sizeof(Elf64_Phdr)`.                                     |

#### `e_ident`: identifying the file

The first 16 bytes of any ELF file are an identification block, not code or data. The first 4 bytes are the magic number, always the same for every ELF file:

```
offset:   0    1    2    3
bytes:  0x7f  'E'  'L'  'F'
```

`woody_woodpacker` checks these 4 bytes first (`ELFMAG`/`SELFMAG` in `<elf.h>`, compared with `ft_memcmp`). If they don't match, the file isn't ELF at all, and processing stops with the `Not an ELF file` error.

One byte further into `e_ident`, at index `EI_CLASS`, a single byte states whether the file is 32-bit or 64-bit:

| Value            | Meaning    |
|------------------|------------|
| `ELFCLASS32` (1) | 32-bit ELF |
| `ELFCLASS64` (2) | 64-bit ELF |

`woody_woodpacker` only accepts `ELFCLASS64`. Combined with `e_machine` being `EM_X86_64`, this check produces the `File architecture not supported. x86_64 only` error for anything else (a 32-bit binary, an ARM binary, etc.).

#### `e_phoff` / `e_phnum`: locating and validating the program header table

`e_phoff` is the file offset where the program header table begins. `e_phnum` is how many entries it has.

Before trusting either, `program_headers_are_valid` runs two passes:

- The table itself must fit: `e_phentsize` has to match `sizeof(Elf64_Phdr)`, and `e_phoff + e_phnum * e_phentsize` can't run past the end of the mapped file.
- Every entry gets walked: its `p_offset`/`p_filesz` must stay inside the file, and for `PT_LOAD` entries, `p_filesz <= p_memsz` and `p_align` must be a power of two.

Any failure rejects the file with `Invalid program header table`, before a single byte gets touched. This is what stops a truncated or hand-corrupted ELF file from being read out of bounds.

### The Program Header Table (`Elf64_Phdr`)

Each entry is one `Elf64_Phdr` struct, describing one **segment**: a contiguous byte range the kernel treats as a single unit when loading the program. Fields this project reads or modifies:

| Field      | Purpose                                                                                         |
|------------|-------------------------------------------------------------------------------------------------|
| `p_type`   | What kind of segment this is (see below).                                                       |
| `p_flags`  | Permissions to map this segment with: readable, writable, executable.                           |
| `p_offset` | Where this segment's bytes start **in the file**.                                               |
| `p_vaddr`  | Where this segment should be mapped **in memory** (virtual address).                            |
| `p_filesz` | How many bytes of this segment exist in the file.                                               |
| `p_memsz`  | How many bytes this segment should occupy in memory (can be larger than `p_filesz`; see below). |
| `p_align`  | Required alignment, almost always the page size, `0x1000` (4096 bytes) on x86_64.               |

#### `p_type`: segment kinds this project cares about

- **`PT_LOAD`**: a segment that must be mapped into memory when the program starts. A typical executable has at least two: one read+execute segment holding code, one read+write segment holding initialized/uninitialized data. `woody_woodpacker` looks for the `PT_LOAD` segment whose virtual address range contains `e_entry`, that's the segment it encrypts. [Section 7](#7-encryption-target-segment-vs-section).

- **`PT_DYNAMIC`**: present in dynamically-linked executables and PIE binaries. Points the dynamic linker (`ld.so`) at the relocation and symbol-resolution tables it needs before `main()` runs.

  `ld.so` reads this segment before the injected stub ever gets control. If it overlaps the segment `woody_woodpacker` is about to encrypt, encrypting it corrupts data the dynamic linker relies on, the packed binary crashes resolving relocations before the stub can decrypt anything back. `woody_woodpacker` detects the overlap and refuses to pack the file.

  Side effect: this is also what rejects re-packing an already-packed `woody`. Its entry now points inside the injected stub, not a plain code segment.

- **`PT_NOTE`**: a segment that normally holds auxiliary metadata (build IDs, ABI tags), not required to run the program. `woody_woodpacker` repurposes it: since its contents are disposable, the entry gets overwritten into a brand-new `PT_LOAD` segment carrying the injected stub, instead of appending a new entry (which would require relocating everything after it). [Section 9](#9-stub-injection). A `PT_NOTE` segment must be present in the input file for this to work.

#### `p_flags`: segment permissions

A bitmask built from three flags, combined with bitwise OR:

| Flag   | Meaning                |
|--------|------------------------|
| `PF_R` | Segment is readable.   |
| `PF_W` | Segment is writable.   |
| `PF_X` | Segment is executable. |

`PF_R | PF_X` (readable and executable, not writable) is the typical permission set for a program's code segment.

The stub needs to overwrite encrypted bytes with decrypted ones in place, so the segment must be writable too. Two ways to get there: call `mprotect` at runtime, or mark the segment writable in the file itself. `woody_woodpacker` takes the second route: `make_text_segment_writable` sets the target segment's `p_flags` to `PF_R | PF_W | PF_X` before writing `woody` out, so the kernel maps it with all three permissions straight from `execve()`. The injected stub's own segment gets the same treatment.

#### File offset vs. virtual address

`p_offset` and `p_vaddr` describe the *same* bytes from two different angles, easy to confuse:

- `p_offset`: where to find those bytes **inside the file on disk**.
- `p_vaddr`: where the kernel places those bytes **in the process's virtual memory** once loaded.

These are different numbers, a segment might start at file offset `0x2000` but map at virtual address `0x401000`. Converting between the two matters for how the stub locates the encrypted segment and the original entry point at runtime, relative to its own position rather than an absolute address only valid for one file. [Section 9](#9-stub-injection).

#### `p_filesz` vs. `p_memsz`

`p_filesz` is how many bytes of a segment exist in the file. `p_memsz` is how many bytes it should occupy once loaded into memory.

When `p_memsz` is larger, the kernel zero-fills the extra space. That's how uninitialized global variables (`.bss`) get memory without taking up file space.

For the stub segment injected by `woody_woodpacker`, both are set to the stub's exact size, code plus its appended keystream. It's fully present in the file, no extra zero-filled space needed.

#### `p_align`

Segments must start at an address that's a multiple of `p_align`, the page size on x86_64 Linux, `0x1000` (4096) bytes. The kernel manages memory in fixed-size pages, and permissions (`PF_R`/`PF_W`/`PF_X`) are only ever set per page, not per byte. That's why placing a new segment (the injected stub) requires rounding its virtual address up to the next page boundary, rather than appending it right after the previous segment ends.

## 7. Encryption Target: Segment vs. Section

An earlier version of this project encrypted an ELF file by walking its **section header table** and encrypting every section marked executable, typically `.text`, `.plt`, and a handful of others. That required tracking a list of regions, one address and one size per matching section.

The current version encrypts differently: it locates the single `PT_LOAD` **segment** whose virtual address range contains `e_entry` (see [Section 6](#6-elf-background)) and encrypts that one contiguous region as a whole. No table of regions needed, one address and one size describe the entire target.

This works because of how the linker lays out a normal executable: all of a program's executable sections are already placed contiguously and loaded by the kernel as a single executable `PT_LOAD` segment. The segment-based approach just reads that information from one header entry instead of scanning a variable-length list of named sections.

Two consequences for the design:

- **Section headers become unnecessary for packing.** The section header table only exists for linking and debugging tools, the kernel never reads it, and a stripped executable may not even have one. Depending on it to locate the code to encrypt would make the packer fragile against binaries built without that information. The program header table, in contrast, is required for the kernel to run the file at all.

- **No region table has to be carried in the packed file.** One address and one size get patched directly into the injected stub as fixed placeholders (see [Section 10](#10-placeholder-patching)), instead of being appended to the output file as a separate data table the stub would need to loop over at runtime. That removes an entire loop, and a whole class of bugs around table layout, from both the packer and the runtime stub.

Locating the target segment by whether it *contains the entry point*, rather than just by its `PF_X` flag, has a side benefit too. It's what makes the `PT_DYNAMIC`-overlap check in [Section 6](#6-elf-background) possible: the packer needs to know precisely which segment it's about to touch before it can ask whether the dynamic linker depends on it too.

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

Decryption regenerates the exact same keystream (same key, nonce, counter) and XORs it against the ciphertext again. XOR is its own inverse (`(a ^ b) ^ b = a`), so encryption and decryption are the same operation given the same keystream.

`woody_woodpacker` uses that property directly: instead of having the runtime stub regenerate the keystream, the packer generates it once and hands the finished bytes to the stub. See [Section 9](#9-stub-injection).

None of the cryptographic strength comes from the XOR step itself, a trivial, well-known operation. It comes entirely from how unpredictable the keystream is, and that unpredictability is produced by mixing a 64-byte input block, the **state**, through many rounds of simple arithmetic. The state is 16 words of 32 bits each (16 × 4 = 64 bytes), conventionally drawn as a 4×4 matrix:

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
|------------|---------------|--------------------|------------------------------------------------------------|
| `[0..3]`   | constant      | 16 bytes           | fixed, identical for every ChaCha20 stream                 |
| `[4..11]`  | key           | 32 bytes (256 bit) | `/dev/urandom`                                             |
| `[12]`     | block counter | 4 bytes            | starts at `1`, incremented once per 64-byte block produced |
| `[13..15]` | nonce         | 12 bytes (96 bit)  | `/dev/urandom`                                             |

All 16 words are required to reproduce a given keystream correctly. If any single word is missing or different, the resulting keystream (and therefore the XOR output) changes, and decryption fails silently rather than with an explicit error.

- **Constant (`[0..3]`)**: 16 fixed bytes defined by the ChaCha20 specification (`CHACHA20_C0`..`CHACHA20_C3` in `inc/woody_woodpacker.h`), the ASCII string `"expand 32-byte k"` split into four 4-byte words. Never changes between uses of the cipher.
- **Key (`[4..11]`)**: 32 random bytes read from `/dev/urandom`. The secret the algorithm's name refers to, though on its own it can't reproduce a keystream without the constant, counter, and nonce alongside it.
- **Block counter (`[12]`)**: identifies which 64-byte block of the stream is currently being generated. Encrypting 200 bytes of data requires 4 blocks (256 bytes of keystream, with the last 56 discarded), so the counter takes the values `1, 2, 3, 4` across those blocks. A different counter value produces a different keystream, even with an identical key and nonce. That's what lets the cipher safely produce more than 64 bytes of keystream from a single key.
- **Nonce (`[13..15]`)**: "number used once", 12 random bytes. Ensures reusing the same key for a different message doesn't reuse the same keystream.

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

The goal is an output that looks chaotic while staying fully deterministic. Same key, nonce, and counter always produce the same keystream, yet flipping a single bit of the key changes roughly half the output bits, with no discernible pattern.

Repeated addition, XOR, and rotation make every word end up influenced by every other word. That's what makes it computationally infeasible to recover the key from an observed keystream.

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

Column and diagonal rounds alternate, ten times each, for 20 rounds total.

After the last round, the 16 mixed words get added, word by word, to the *original* (pre-mixing) state, one final time. That addition is what produces the finished 64-byte keystream block.

### How This Maps to the Project's Source

`src/chacha20.c` implements the algorithm described above, entirely on the host side. There is no ChaCha20 implementation in `src/stub.S` (see [Section 11](#11-the-runtime-stub-stubs)):

- `prepare_chacha20_stream` builds the initial state: `states[0..3]` are the fixed constants, `states[12]` is set to `1`, and `states[4..11]` (key) plus `states[13..15]` (nonce) are read from `/dev/urandom` in one pair of calls.
- `chacha20_quarter_round` implements the four-step operation from [Quarter Rounds](#quarter-rounds) on four `uint32_t` pointers.
- `chacha20_block` copies the state into a working buffer, then runs the 10-iteration loop (8 quarter-round calls each, alternating column and diagonal groupings). It adds the mixed words back onto the original state, and serializes the 16 resulting words into a 64-byte keystream buffer, least-significant byte first.
- `chacha20_process` is the shared block-stepping loop. It calls `chacha20_block` once per 64-byte chunk of `len` bytes, advances the block counter (`states[12]`) between calls, and either XORs the chunk in place or copies the raw keystream out, depending on the `apply_xor` flag. `chacha20_encrypt` and `chacha20_generate_keystream` are thin wrappers around it: the first XORs the executable segment at encryption time, the second extracts the keystream as plain bytes to append to the stub (see [Section 9](#9-stub-injection)).
- `woody_prepare_cipher` calls `prepare_chacha20_stream`, then snapshots the fresh state into `chacha_initial_state` before any block gets consumed. That untouched copy matters: by the time the stub gets built, the working `chacha_state` has already been advanced by encrypting the segment. `chacha20_generate_keystream` runs against the snapshot instead, so the keystream starts from block `1` again.

The `key_value` printed to standard output is the 32-byte key, `states[4..11]`, printed as one continuous hex string by `woody_encrypt_segment` right after encryption.

## 9. Stub Injection

Injecting the runtime stub means adding a new executable region to the file, and pointing the entry point at it, without changing anything the original binary needs to keep running correctly. Done by `woody_inject_payload` in `src/stub.c`.

### Building the Stub Payload

The compiled stub code (`src/stub.S`, bracketed by the `woody_stub_start`/`woody_stub_end` symbols) is fixed size, identical for every input file. `copy_stub_template` allocates a buffer big enough for that code *plus* the target segment's size (`stub_size = template_size + text_size`), and copies the code into the front of it.

The tail is left empty, for the keystream. `patch_stub_parameters` fills it in with `chacha20_generate_keystream` (see [Section 8](#8-the-chacha20-cipher)). Carrying a precomputed keystream instead of key/nonce/counter values keeps the runtime stub simple: it never runs the cipher, it just XORs two byte buffers together (see [Section 11](#11-the-runtime-stub-stubs)).

### Changing the `PT_NOTE` Segment

Appending a brand-new entry to the program header table would push every later byte further into the file, invalidating every other segment's `p_offset`. To avoid that, `woody_woodpacker` reuses an existing entry instead: `install_stub` scans for a `PT_NOTE` segment (see [Section 6](#6-elf-background)) and overwrites that entry in place, turning it into a new `PT_LOAD` segment for the stub. No `PT_NOTE` segment means no safe slot to repurpose, and injection fails.

### Placing the Stub in Memory

`get_highest_pt_load_vaddr` walks every `PT_LOAD` segment and tracks the highest virtual address in use (`p_vaddr + p_memsz`). The new stub segment goes right after that point, rounded up to the next page boundary, so it can't overlap any segment the original program relies on.

Its file offset is computed separately: the input file's size, rounded up to the next page boundary. That's where the stub's bytes land when `woody` gets written out ([Section 4](#4-build-system)).

### Repurposed Segment Fields

The repurposed entry is rewritten with the following fields:

| Field                 | New value                            | Reason                                                                                                                |
|-----------------------|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `p_type`              | `PT_LOAD`                            | The segment must now be mapped into memory at load time.                                                              |
| `p_flags`             | `PF_R \| PF_W \| PF_X`               | Stub executes and writes decrypted bytes in place. No runtime `mprotect` needed (see [Section 6](#6-elf-background)). |
| `p_offset`            | the aligned end of the original file | Where the stub's bytes get appended when `woody` is written out (`create_woody_executable`).                          |
| `p_filesz`, `p_memsz` | `stub_size` (code + keystream)       | The stub is fully present in the file, no extra zero-filled space needed.                                             |
| `p_vaddr`, `p_paddr`  | as computed above                    | Where the stub is mapped at runtime.                                                                                  |
| `p_align`             | `0x1000`                             | Required page alignment.                                                                                              |

`elf.ehdr->e_entry` gets overwritten with this new `p_vaddr`. The kernel now jumps to the stub first, not the program's original startup code.

Once the segment fields and the keystream are both in place, `make_text_segment_writable` flips the *original* target segment's `p_flags` to `PF_R | PF_W | PF_X` too, same reason as above.

### Making the Stub Position-Independent

The stub can't rely on any address being fixed in advance, since where it ends up in the file (and in memory) depends on the input binary being packed. Rather than patch in absolute addresses, `patch_stub_parameters` computes two values *relative to the stub's own new `p_vaddr`*:

- `text_vaddr - stub_vaddr`: how far the encrypted segment sits from the stub's starting address. Lets the stub find the bytes it needs to decrypt without knowing its own runtime load address in advance.
- `original_entry - stub_vaddr`: the same treatment applied to the original entry point, so the stub can jump back to the real program once decryption is done.

Both offsets, together with the segment's size, get written into the stub's own bytes by `patch_stub_parameters`, see [Section 10](#10-placeholder-patching).

## 10. Placeholder Patching

The stub's machine code is fixed ahead of time, in `src/stub.S`. At assembly time it can't know the entry-point offset or the encrypted segment's address and size, those depend on the specific file being packed.

`woody_woodpacker`'s fix: embed recognizable sentinel values in the stub's data at assembly time, then overwrite them with the real values once they're known.

### Sentinel Constants

`src/stub.S` reserves one 8-byte slot per runtime value, each initialized to a distinctive placeholder constant unlikely to occur by coincidence in real program data:

```
.Ltext_rel:  .quad 0x1111111111111111   ; encrypted segment address, relative to the stub
.Ltext_size: .quad 0x2222222222222222   ; encrypted segment size
.Lentry_rel: .quad 0x3333333333333333   ; original entry-point offset, relative to the stub
```

These same constants are defined in `inc/woody_woodpacker.h` (`STUB_MARKER_TEXT_REL`, `STUB_MARKER_TEXT_SIZE`, `STUB_MARKER_ENTRY_REL`), so the C code and the assembly data agree on exactly which bytes to look for.

No key or nonce placeholder exists here, unlike an earlier design. The tail of the stub buffer already carries the finished keystream bytes (see [Section 9](#9-stub-injection)), nothing cipher-related is left to look up by sentinel.

### Scanning and Replacing

`patch_stub_parameters`, in `src/stub.c`, drives the process. For each of the three values: `find_marker` walks every byte offset of the stub, reinterpreting each 8-byte window as a `uint64_t`, comparing it against the sentinel. `patch_marker_u64` overwrites the first match with the real value via `memcpy`.

If a sentinel isn't found, patching fails and injection aborts. No `woody` file ships with stale placeholder bytes still in it.

### Why Sentinel Values Instead of Fixed Offsets

An alternative design would hardcode the byte offset of each value inside the compiled stub directly. That's fragile: any change to `src/stub.S` that shifts surrounding code or data, even one unrelated to these values, silently invalidates every hardcoded offset.

Searching for a unique constant instead sidesteps that. The patching logic keeps working as long as the constant stays somewhere in the assembled stub, regardless of where the assembler places it.

## 11. The Runtime Stub (`stub.S`)

Once `woody` is launched, the injected stub is the first code to run ([Section 9](#9-stub-injection)). Written in x86_64 assembly, for direct control over registers and syscalls.

It's deliberately small, three jobs: announce the binary is packed, XOR the encrypted segment against the keystream carried in its own tail, hand control back to the original program. No cipher logic, block loop, or key material lives in the assembly. That work already happened on the host side ([Section 8](#8-the-chacha20-cipher), [Section 9](#9-stub-injection)).

### Finding Its Own Runtime Address

The stub has no fixed address to work from, the same bytes must work no matter where in memory the kernel loads them.

`woody_stub_start` calls the very next instruction and pops the return address off the stack (`call .Lget_stub_base` / `pop r12`), the standard `call/pop` trick for reading the instruction pointer on x86_64. It then subtracts the 5 bytes of the `call` instruction itself, landing `r12` exactly on the stub's own load address.

### Announcing the Packed Binary

Before touching any register the rest of the program might still need, the stub saves `rdx` (the one register it uses beyond the syscall-clobbered set), then issues a `write` syscall printing the `....WOODY....` marker straight from the stub's own `.Lbanner` data.

### Locating the Encrypted Segment and Decrypting It

`.Ltext_rel`, patched at pack time to hold the segment's address relative to the stub ([Section 10](#10-placeholder-patching)), gets added to `r12`, that's the segment's actual runtime address. `.Lkeystream`, the label right after the stub's fixed-size code, points at the keystream bytes `patch_stub_parameters` appended.

`.Lxor_loop` walks both buffers one byte at a time, for `.Ltext_size` iterations, XORing each encrypted byte with the matching keystream byte in place. Same operation `chacha20_encrypt` ran at pack time, just in reverse, XOR being its own inverse ([Section 8](#8-the-chacha20-cipher)).

No `mprotect` call needed here: the target segment was already mapped `PF_R | PF_W | PF_X` by the kernel at `execve()` time ([Section 9](#9-stub-injection)).

### Returning to the Original Program

Once the XOR loop finishes (or immediately, if `.Ltext_size` was zero), the stub restores `rdx`. It computes the real program's entry point the same way it located the encrypted segment, `r12` plus `.Lentry_rel`, and jumps there.

Control passes to the original program's startup code, now fully decrypted in memory. Every register is left exactly as the kernel set it up, so the rest of execution looks like running the unpacked binary directly.

## 12. Error Handling

Every operation in `woody_woodpacker` is checked, and every failure path converges on a single helper, `error()` in `src/error.c`:

```c
uint8_t error(char *msg) {
    printf("%s\n", msg);
    return (EXIT_FAILURE);
}
```

It writes a descriptive message to standard output and returns `EXIT_FAILURE`. Every calling function propagates that upward immediately, no further work attempted.

`create_woody_executable`, the function that opens `woody` for writing, only runs once validation, target-segment lookup, encryption, and stub injection have all succeeded. No `woody` file is ever created, partially or otherwise, when packing fails.

`pack_file` also guarantees `woody_cleanup` runs on every path, success or failure: frees the stub buffer, unmaps the input file.

### Error Conditions

| Cause                                                                        | Message                                                                     | Where                       |
|------------------------------------------------------------------------------|-----------------------------------------------------------------------------|-----------------------------|
| Wrong number of command-line arguments                                       | `strerror(EINVAL)`                                                          | `main`                      |
| Input file cannot be opened, `lseek`'d, or `mmap`'d                          | `strerror(errno)`                                                           | `load_elf_file`             |
| File is smaller than an ELF header, or its magic bytes don't match           | `Not an ELF file`                                                           | `load_elf_file`             |
| File is not `ELFCLASS64` / `EM_X86_64`                                       | `File architecture not supported. x86_64 only`                              | `load_elf_file`             |
| Program header table doesn't fit the file, or an entry's offsets/sizes don't | `Invalid program header table`                                              | `load_elf_file`             |
| No `PT_LOAD` segment contains the entry point                                | `No executable segment found`                                               | `woody_find_target_segment` |
| A `PT_DYNAMIC` segment overlaps the target segment (already packed, or PIE)  | `entry is inside the dynamic segment; cannot pack an already-packed binary` | `woody_find_target_segment` |
| `/dev/urandom` cannot be opened or read                                      | `strerror(errno)`                                                           | `prepare_chacha20_stream`   |
| Stub injection fails (no `PT_NOTE`, or a sentinel placeholder wasn't found)  | `Cannot inject the entry stub`                                              | `process_file`              |
| `woody` cannot be opened or written                                          | *(none — returns `EXIT_FAILURE` directly)*                                  | `create_woody_executable`   |

### Scope

This covers `woody_woodpacker` itself, at packing time. The subject's requirement that "the encrypted program must never crash" targets the *output*, `woody`.

Packing only ever completes on a file that already passed every check above. So the runtime stub ([Section 11](#11-the-runtime-stub-stubs)) can assume it's always working with a well-formed segment, entry point, and keystream. No need to re-validate any of it.

## 13. Project Structure

```
woody-woodpacker/
├── src/
│   ├── woody_woodpacker.c   entry point: argument check, orchestration
│   ├── elf.c                mmap, validation, and cleanup of the input file
│   ├── program_headers.c    program header validation and segment lookup
│   ├── chacha20.c           ChaCha20 state, block cipher, segment encryption
│   ├── stub.c                stub buffer assembly, placeholder patching, injection
│   ├── stub.S                the actual runtime stub, assembled and linked directly
│   ├── output.c              writes the final `woody` file
│   ├── error.c                shared error-reporting helper
│   └── debug.c                optional printf-based ELF/program-header dumps
├── inc/
│   ├── woody_woodpacker.h    t_woody struct, constants, placeholder markers, prototypes
│   ├── elf_internal.h        t_elf struct and ELF-loading prototypes
│   └── debug.h                prototypes for debug.c
├── docs/
│   ├── en.subject.pdf        project specification
│   └── resources/            sample input binaries used for manual testing
├── libft/                    C helpers, pulled in as a Git submodule
├── Dockerfile
├── docker-compose.yaml
├── LICENSE
├── makefile
└── README.md
```

| Component                | Responsibility                                                                                                                                                                                              |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `src/woody_woodpacker.c` | `main()` and the pipeline from [Section 5](#5-architecture): validates arguments, drives `pack_file`, guarantees cleanup on every path.                                                                     |
| `src/elf.c`              | `load_elf_file`: opens, size-checks, `mmap`s, and validates the input file; `woody_cleanup`.                                                                                                                |
| `src/program_headers.c`  | `program_headers_are_valid`, `get_highest_pt_load_vaddr`, `woody_find_target_segment`, `make_text_segment_writable` ([Section 6](#6-elf-background), [Section 7](#7-encryption-target-segment-vs-section)). |
| `src/chacha20.c`         | Building the initial state, the quarter round and block functions, encrypting the segment and generating the standalone keystream ([Section 8](#8-the-chacha20-cipher)).                                    |
| `src/stub.c`             | Assembling the stub buffer, repurposing the `PT_NOTE` segment, patching its placeholder values ([Section 9](#9-stub-injection), [Section 10](#10-placeholder-patching)).                                    |
| `src/stub.S`             | The runtime stub logic, compiled directly into the binary ([Section 11](#11-the-runtime-stub-stubs)).                                                                                                       |
| `src/output.c`           | `create_woody_executable`: writes the original file, page-aligned padding, then the stub, as `woody`.                                                                                                       |
| `inc/woody_woodpacker.h` | The `t_woody` struct, constants shared across `.c` files (placeholder markers, ChaCha20 constants), function prototypes.                                                                                    |
| `inc/elf_internal.h`     | The `t_elf` struct and the small set of ELF-loading prototypes shared between `elf.c` and `program_headers.c`.                                                                                              |
| `docs/en.subject.pdf`    | The original project specification this README's requirements are drawn from.                                                                                                                               |
| `libft/`                 | A small vendored C standard-library helper set, fetched automatically as a Git submodule ([Section 4](#4-build-system)), used here for `ft_memcpy`/`ft_memcmp`.                                             |

## 14. Testing

No automated test suite. Verified by building a small executable, packing it, and confirming the packed result behaves identically to the original, the same way the project's subject itself describes checking it.

```
$ gcc -o docs/resources/sample docs/resources/sample.c
$ make

$ ./docs/resources/sample
Hello, World!

$ ./woody_woodpacker docs/resources/sample
key_value: <32-byte hex key>

$ ./woody
....WOODY....
Hello, World!
```

The `....WOODY....` marker prints first, followed by exactly what the original program would have printed, confirming the stub decrypted the segment correctly before handing control back. Exit status is checked with `echo $?` after each run and compared against the unpacked original.

This same procedure, compile a small real program, run `woody_woodpacker` on it, compare output and exit status against the original, is how any other candidate input can be checked.

## 15. References

- **[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)**, "ChaCha20 and Poly1305 for IETF Protocols". Defines the ChaCha20 state layout, quarter round, and block function this project implements in `src/chacha20.c`. [Section 8](#8-the-chacha20-cipher).
- **`docs/en.subject.pdf`**. The project's own specification, source of every mandatory requirement in this document, including the exact error message wording in [Section 12](#12-error-handling).
- **`elf(5)`** man page, and the ELF64 struct definitions in `<elf.h>`. Reference used for `Elf64_Ehdr` and `Elf64_Phdr` ([Section 6](#6-elf-background)).
- **[ELF Object File Format](https://gabi.xinuos.com/elf.pdf)**. The full ELF specification, including the program and section header formats summarized in [Section 6](#6-elf-background).
- **`mmap(2)`** man page. Covers the page-aligned memory mapping this project relies on when mapping the input file for editing (`load_elf_file`).
- **[libft](https://github.com/AingeruAlvarezSanchez/Libft)**. The vendored C standard-library helper set this project builds on ([Section 4](#4-build-system), [Section 13](#13-project-structure)).
</content>
