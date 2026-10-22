# GS290 Native Access Probe (research)

This is a measurable AROMA Java VM experiment, **NOT a proven native exploit**.
It belongs in LG-GS290-Rebirth, not J2ME-DevSpace main.

Version 0.1.2 adds a "Save TXT" action using the standard optional JSR-75
FileConnection API. It lists available storage roots, lets the user set a
filename, and saves a full UTF-8 report with JVM properties, Java class checks,
DEFLATE results and the RMS marker. Existing files are never overwritten.
File write/read permissions are requested as **optional**; the handset may
prompt for approval. If JSR-75 is absent, denied, or no writable storage exists,
the MIDlet shows an error while keeping its diagnostics available.

Update/install both 0.1.2 JAR and JAD together to preserve the original
MIDlet name/vendor/class; the MIDlet version is incremented for in-place
installation upgrades. The compiler must support project optional_apis
["jsr75-file"] and optional_permissions; these are only build-time API references
and JAD/manifest metadata, never shipped as JSR-75 implementations.

The MIDlet uses CLDC 1.1 / MIDP 2.0 and 45.3 StackMap bytecode produced by
the merged J2ME-DevSpace toolchain. It never flashes the handset.

## What it reports

- Java API class-presence tests: Unsafe, FileConnection, optional LG Canvas.
  Class presence is NOT native execution or privilege escalation.
- Real system properties, CLDC, MIDP and Canvas dimensions.
- A persistent RMS record ARMED set before loading a compressed JAR resource.
  If interrupted, next start shows PREVIOUS RUN INTERRUPTED, only evidence
  of an incomplete Java call, NOT RCE.
- Resource read result or Java exception type if control returns.
- ARM REGISTERS: NO API, RAW MEMORY: NO API, NATIVE EXEC: UNPROVEN.

## Safe control build and test

Use Python 3, host Java 8+ and merged J2ME-DevSpace phonebuild tool.

~~~powershell
python .\tools\phonebuild\main.py --workspace . --project .\experiments\j2me-native-probe
python .\experiments\j2me-native-probe\tools\pack_probe.py --input .\experiments\j2me-native-probe\dist\GS290NativeProbe.jar --jad .\experiments\j2me-native-probe\dist\GS290NativeProbe.jad --out .\experiments\j2me-native-probe\dist\GS290NativeProbe-Control.jar --mode control
~~~

The control JAR contains a valid DEFLATE resource. Install this JAR+JAD
from GitHub Actions before considering invalid input tests.

## Opt-in malformed DEFLATE (not published as a CI device artifact)

Unicorn v7's 78-byte test with SHA256
702e33e26902e549fad41c7f56fdd4b4319f5616c8164bfe2e7b10bc966305a2
produced three bytes of physical overflow in isolated V10C ARM code.

To create an intentionally malformed ZIP entry in a separate JAR,
use the packing script with --mode huffman-oob and the explicit flag
--i-accept-phone-crash-risk.

The handset may reject it, terminate the MIDlet or freeze. Installed
firmware V10k is unverified relative to analyzed V10C; back up the
device before physical testing, and do not use on irreplaceable data.

Neither a Java exception nor an interrupted RMS marker proves
native code execution, arbitrary address read/write or commands.

## Requirements for actual native success

Demonstrate the unsigned JAR reaches the same decoder on V10k, prove
that corruption of stack-local sp+0x14c affects a usable control
primitive, and independently observe a controlled ARM PC transition
that writes a harmless marker into isolated scratch RAM.

See analysis/JVM_DYNAMIC_HUFFMAN_V7_V8.md for evidence.
