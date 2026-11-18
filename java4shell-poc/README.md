# Java4Shell (CVE-2026-114938) proof of concept

Heap buffer overflow in OpenJDK's AVX-512 accelerated Base64 decoder intrinsic
(`java.util.Base64$Decoder.decodeBlock`, `StubRoutines::base64_decodeBlock` on x86-64).
Discovered by Calif. Mechanics taken from Oligo Security's write-up of 2026-11-17:
<https://www.oligo.security/blog/java4shell-oligo-blocks-the-zero-day-before-the-patch>

## The bug in one paragraph

The input is 64 valid Base64 characters followed by one `=` (65 bytes). The AVX-512 main loop decodes
the first 64 characters into 48 bytes. The tail routine receives the lone `=`: it computes
`(1 / 4) * 3 = 0` output bytes, sees padding and decrements, and the unsigned value wraps to
`0xFFFFFFFFFFFFFFFF`. `bzhiq` only uses the low 8 bits of that index; 255 is at or above 64, so no mask
bits are cleared and the masked store writes all 64 bytes at offset 48 of the 50-byte `byte[]` Java
allocated. 62 bytes land on whatever object follows on the heap. Older OpenJDK 17 builds need
128 characters + `=` instead because their vector-path threshold is higher.

## Files

| File | Purpose |
|---|---|
| `Java4ShellPoC.java` | Single-file PoC with `detect`, `crash` and `pem` modes. Runs on JDK 11+; the affected intrinsic was introduced in JDK 17 on x86-64. |
| `payloads/trigger-65.b64` | Raw 65-byte trigger, no trailing newline |
| `payloads/trigger-129.b64` | 129-byte variant for older OpenJDK 17 builds |
| `payloads/trigger.pem` | Trigger wrapped as a PEM certificate, the delivery path shown in the write-up |

A trailing newline after the `=` changes the tail and defuses the trigger, so keep the `.b64` files byte-exact.

## Usage

```bash
java Java4ShellPoC.java                        # detect mode, safe, exit status 1 if vulnerable
```

```bash
java Java4ShellPoC.java crash                  # corrupts a neighbouring object, expect a JVM abort
```

```bash
java Java4ShellPoC.java pem --out trigger.pem  # CertificateFactory delivery path
```

Options: `--prefix N --tail S` for a custom probe (N must be a multiple of 4), `--warmup N`, `--rounds N`.
Exit status: 0 nothing observed, 1 out-of-bounds write or corruption observed, 2 usage error.

### detect mode (default, safe)

Calls `Base64.Decoder.decode(byte[] src, byte[] dst)` with a dst that is 256 bytes larger than the
decoder needs and pre-filled with a sentinel. The out-of-bounds store therefore lands inside our own
array, where it is measured, instead of on the heap. Every probe runs against the basic, URL and MIME
decoders with two different sentinels. Before every attempt the decoder is called 100,000 times with
valid input: the intrinsic only exists in C2-compiled code, and the IllegalArgumentException a probe
provokes deoptimises `decode0`, after which the interpreter silently uses the pure-Java decoder.

Verified on OpenJDK 21.0.13.0.3 (Ubuntu 24.04), Intel Xeon with avx512vbmi, UseAVX=3:

```
[basic] 64+'='      65 B  threw IllegalArgumentException: Input byte array has wrong 4-byte ending unit
        WROTE 64 bytes at offsets 48..111, 62 of them past the 50-byte buffer decode(byte[]) allocates   <-- HEAP OVERFLOW
        first bytes written: 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69
...
VERDICT: VULNERABLE to CVE-2026-114938.
```

Observations from that run:

- The basic and URL decoders overflow for every probe: `=`, `==`, `A=` and `AA=` tails after 64, 128 or 256 characters.
- The MIME decoder is not affected on this build; the stub leaves MIME input to the Java code.
- The overflow data is deterministic: the repeating pattern `69 a6 9a`, with the first one or two bytes depending on the tail characters.
- With `-XX:UseAVX=2` or `-XX:-UseBASE64Intrinsics` the tool reports no out-of-bounds write and exits 0, which confirms both interim mitigations.

### crash mode

Allocates an exactly-sized dst and a 64-byte victim array right behind it, decodes the trigger, then
forces a GC. On the vulnerable JDK 21 the victim's length field read back as -1700370022
(0x9A69A69A, the overflow pattern) and the collector died with SIGSEGV in
`G1FullGCMarker::mark_and_push`, leaving an `hs_err_pid*.log`.

### pem mode

Wraps the trigger in `-----BEGIN CERTIFICATE-----` markers and calls
`CertificateFactory.generateCertificate()`. `javap` on this JDK 21 shows `X509Factory.readOneBlock`
calling `Base64.getDecoder().decode(byte[])`, so PEM input reaches the vulnerable decoder. The decoder
allocates its own exactly-sized buffer on that path, so the overflow lands in free heap space and
nothing visible happens apart from the `CertificateException`. This mode exists to exercise the
real-world delivery path, for example under a runtime protection tool.

## Exposure checklist (from the write-up)

1. An affected OpenJDK build with the hardware-accelerated Base64 decoder.
2. The AVX-512 path enabled: a CPU with avx512bw, avx512vl and avx512vbmi, `UseAVX=3`, `UseBASE64Intrinsics=true`.
3. Untrusted Base64 reaching the decoder: PEM certificates, tokens, API payloads.

Fix: update the JDK. Interim: `-XX:UseAVX=2` or `-XX:-UseBASE64Intrinsics`, verified with this tool.

## Scope

This demonstrates and measures the memory corruption only. It contains no heap grooming and no
code-execution chain. Run it only against JVMs you own or are authorised to test.
