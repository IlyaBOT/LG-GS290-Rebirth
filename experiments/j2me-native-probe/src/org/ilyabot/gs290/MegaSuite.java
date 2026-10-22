package org.ilyabot.gs290;

import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;
import javax.microedition.io.Connector;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;

/**
 * Bounded, unprivileged end-to-end Java ME VM/loader regression suite.
 * No malformed DEFLATE, raw native writes or device reconfiguration.
 * All exceptions become report records; one unsupported API never aborts suite.
 */
public final class MegaSuite {
    public interface Progress {
        void onProgress(String summary);
    }
    private final MIDlet midlet;
    private final Class resourceOwner;
    private final Progress listener;
    private final StringBuffer report = new StringBuffer(5000);
    private int passed;
    private int failed;
    private int unsupported;
    private int index;
    private static final String RESOURCE = "/GS290ProbePayload.bin";

    public MegaSuite(MIDlet owner, Class resourceClass, Progress progress) {
        midlet = owner;
        resourceOwner = resourceClass;
        listener = progress;
    }

    public String execute() {
        report.append("GS290 J2ME MEGASUITE v0.2.0\r\n");
        report.append("Mode: SAFE CONTROL; NO NATIVE RCE\r\n");
        report.append("Start epoch ms: ").append(System.currentTimeMillis()).append("\r\n");
        section("SYSTEM AND VM");
        testProperty("configuration", "microedition.configuration");
        testProperty("profiles", "microedition.profiles");
        testProperty("platform", "microedition.platform");
        testProperty("locale", "microedition.locale");
        testProperty("file version", "microedition.io.file.FileConnection.version");
        testProperty("encoding", "microedition.encoding");
        testProperty("hostname", "microedition.hostname");
        testProperty("J2ME version", "java.version");
        check("clock", System.currentTimeMillis() > 0,
              "epoch_ms=" + System.currentTimeMillis());
        check("calendar", Calendar.getInstance().get(Calendar.YEAR) >= 2000,
              "year=" + Calendar.getInstance().get(Calendar.YEAR));
        section("CAPABILITIES AND SANDBOX");
        testClass("java.lang.Thread");
        testClass("java.io.InputStream");
        testClass("javax.microedition.lcdui.Canvas");
        testClass("javax.microedition.rms.RecordStore");
        testClass("javax.microedition.io.file.FileConnection");
        testClass("javax.microedition.io.file.FileSystemRegistry");
        testClass("javax.microedition.media.Manager");
        testClass("javax.wireless.messaging.MessageConnection");
        testClass("javax.microedition.m3g.Graphics3D");
        testClass("javax.bluetooth.LocalDevice");
        testClass("javax.microedition.pim.PIM");
        testClass("sun.misc.Unsafe");
        testClass("com.lge.lcdui.LGCanvas");
        testPermission("javax.microedition.io.Connector.file.read");
        testPermission("javax.microedition.io.Connector.file.write");
        testPermission("javax.microedition.io.Connector.http");
        testPermission("javax.microedition.io.Connector.https");
        testPermission("javax.microedition.io.Connector.socket");
        section("MATH, ENCODING AND ARRAYS");
        testMath();
        testBytes();
        testArrays();
        testString();
        section("JAVA MEMORY AND THREADS");
        testMemory();
        testThread();
        section("ARCHIVE / JAVA RESOURCE LOADER");
        readResource("raw resource read #1", false);
        readResource("raw resource read #2", true);
        testMissingResource();
        section("RMS TRANSACTIONS");
        testRms();
        section("JSR-75 FILESYSTEM INVENTORY");
        testFilesystem();
        section("CONCLUSIONS");
        report.append("Passed=").append(passed)
              .append(" Failed=").append(failed)
              .append(" Unsupported=").append(unsupported).append("\r\n");
        report.append("No CPU registers, arbitrary native RAM or PC control tested.\r\n");
        report.append("No shell commands or malformed JAR inputs attempted.\r\n");
        report.append("A Java error / stalled VM is NOT proof of RCE.\r\n");
        report.append("End epoch ms: ").append(System.currentTimeMillis()).append("\r\n");
        return report.toString();
    }

    private void section(String name) {
        report.append("\r\n=== ").append(name).append(" ===\r\n");
        if (listener != null) listener.onProgress("SECTION: " + name);
    }
    private void item(String status, String name, String detail) {
        index++;
        report.append('[').append(index).append("] ").append(status).append(' ')
              .append(name).append(": ").append(detail).append("\r\n");
        if ("PASS".equals(status)) passed++;
        else if ("FAIL".equals(status)) failed++;
        else unsupported++;
        if (listener != null) {
            listener.onProgress(index + " checks; PASS=" + passed + " FAIL=" + failed
                    + " N/A=" + unsupported + "; " + name);
        }
    }
    private void check(String name, boolean ok, String detail) {
        item(ok ? "PASS" : "FAIL", name, detail);
    }
    private String error(Throwable ex) {
        return ex.getClass().getName() + (ex.getMessage() == null
                ? "" : " / " + ex.getMessage());
    }
    private void testProperty(String label, String key) {
        try {
            String value = System.getProperty(key);
            item(value != null ? "PASS" : "N/A", label,
                    value == null ? "(unset)" : value);
        } catch (Throwable e) {
            item("N/A", label, error(e));
        }
    }
    private void testClass(String name) {
        try {
            Class.forName(name);
            item("PASS", "CLASS " + name, "FOUND; PRESENCE IS NOT PRIVILEGE");
        } catch (ClassNotFoundException ex) {
            item("N/A", "CLASS " + name, "NOT INSTALLED");
        } catch (Throwable ex) {
            item("N/A", "CLASS " + name, error(ex));
        }
    }
    private void testPermission(String name) {
        try {
            int state = midlet.checkPermission(name);
            String desc = state == 1 ? "ALLOWED" : state == 0
                    ? "DENIED" : "UNKNOWN_OR_PROMPT";
            item("PASS", "PERMISSION " + name, desc + " (" + state + ")");
        } catch (Throwable ex) {
            item("N/A", "PERMISSION " + name, error(ex));
        }
    }
    private void testMath() {
        int a = (int)0xF1234567L;
        int rolled = (a << 3) | (a >>> 29);
        int back = (rolled >>> 3) | (rolled << 29);
        check("32-bit rotation", back == a,
                "input=0xF1234567 roundtrip=" + (back == a));
        long v = ((long)0xffffffff & 0xffffffffL) + 1L;
        check("unsigned 32-bit into long", v == 4294967296L, "value=" + v);
        int overflow = 2147483647 + 1;
        check("signed integer wrap", overflow == -2147483648,
                "wrapped=" + overflow);
    }
    private void testBytes() {
        byte[] data = new byte[] {(byte)255, (byte)0, (byte)128, (byte)1};
        int sum = 0;
        for (int i = 0; i < data.length; i++) sum += data[i] & 0xff;
        check("unsigned byte conversion", sum == 384, "sum=" + sum);
        int le = (data[0] & 0xff) | ((data[1] & 0xff) << 8);
        check("little endian manual read", le == 255, "word=" + le);
    }
    private void testArrays() {
        try {
            int[] src = new int[] {3, 7, 11, 19, 23};
            int[] dst = new int[8];
            System.arraycopy(src, 1, dst, 2, 3);
            check("arraycopy ranges", dst[2] == 7 && dst[3] == 11
                  && dst[4] == 19 && dst[0] == 0, "offset=2 len=3");
        } catch (Throwable e) {
            item("FAIL", "arraycopy ranges", error(e));
        }
        try {
            int[] array = new int[4];
            array[4] = 1;
            item("FAIL", "bounds-check", "write past Java array succeeded");
        } catch (ArrayIndexOutOfBoundsException good) {
            item("PASS", "bounds-check", "Java array write rejected");
        } catch (Throwable e) {
            item("FAIL", "bounds-check", error(e));
        }
    }
    private void testString() {
        try {
            String s = "GS290: ТЕСТ: €";
            byte[] encoded = s.getBytes("UTF-8");
            String decoded = new String(encoded, "UTF-8");
            check("UTF-8 encode/decode", s.equals(decoded),
                    "encoded_bytes=" + encoded.length);
        } catch (Throwable e) {
            item("N/A", "UTF-8 encode/decode", error(e));
        }
        try {
            String val = "AA,BB,CC";
            check("substring/indexOf", val.substring(3, 5).equals("BB")
                    && val.indexOf("CC") == 6, val);
        } catch (Throwable e) {
            item("FAIL", "substring/indexOf", error(e));
        }
    }
    private void testMemory() {
        Runtime rt = Runtime.getRuntime();
        report.append("HEAP BEFORE: total=").append(rt.totalMemory())
              .append(" free=").append(rt.freeMemory()).append("\r\n");
        int[] lengths = new int[] {16384, 65536, 131072, 262144};
        for (int i = 0; i < lengths.length; i++) {
            try {
                byte[] b = new byte[lengths[i]];
                int checksum = 0;
                for (int n = 0; n < b.length; n += 257) {
                    b[n] = (byte)(n & 0x7f);
                    checksum += b[n] & 0xff;
                }
                check("heap " + lengths[i] + " bytes", b.length == lengths[i],
                      "pattern_checksum=" + checksum);
                b = null;
            } catch (OutOfMemoryError e) {
                item("N/A", "heap " + lengths[i] + " bytes", "OUT OF MEMORY");
                break;
            } catch (Throwable e) {
                item("FAIL", "heap " + lengths[i] + " bytes", error(e));
                break;
            }
        }
        rt.gc();
        report.append("HEAP AFTER GC: total=").append(rt.totalMemory())
              .append(" free=").append(rt.freeMemory()).append("\r\n");
    }
    private void testThread() {
        final int[] shared = new int[] {0};
        try {
            Thread t = new Thread(new Runnable() {
                public void run() {
                    for (int i = 0; i < 256; i++) shared[0] += i;
                }
            });
            t.start();
            t.join(1500);
            check("thread start/join", !t.isAlive() && shared[0] == 32640,
                    "sum=" + shared[0] + " alive=" + t.isAlive());
        } catch (Throwable e) {
            item("FAIL", "thread start/join", error(e));
        }
    }
    private void readResource(String label, boolean buffered) {
        InputStream stream = null;
        try {
            stream = resourceOwner.getResourceAsStream(RESOURCE);
            if (stream == null) {
                item("N/A", label, "RESOURCE NOT INCLUDED");
                return;
            }
            int bytes = 0;
            int sum = 0;
            if (buffered) {
                byte[] buf = new byte[97];
                int n;
                while (bytes < 4096 && (n = stream.read(buf)) >= 0) {
                    if (n == 0) break;
                    for (int i = 0; i < n; i++) sum = (sum + (buf[i] & 255)) & 0xffff;
                    bytes += n;
                }
            } else {
                int b;
                while (bytes < 4096 && (b = stream.read()) >= 0) {
                    sum = (sum + b) & 0xffff;
                    bytes++;
                }
            }
            check(label, bytes == 55 && sum == 3620,
                  "bytes=" + bytes + " sum=" + sum
                  + " reference=55/3620 (previous GS290 control)");
        } catch (Throwable e) {
            item("FAIL", label, error(e));
        } finally {
            if (stream != null) {
                try { stream.close(); } catch (Throwable ignored) { }
            }
        }
    }
    private void testMissingResource() {
        try {
            InputStream stream = resourceOwner.getResourceAsStream("/__NONEXISTENT_290__.bin");
            if (stream != null) {
                stream.close();
                item("FAIL", "missing resource", "nonexistent stream was returned");
            } else {
                item("PASS", "missing resource", "returned null");
            }
        } catch (Throwable e) {
            item("N/A", "missing resource", error(e));
        }
    }
    private void testRms() {
        String name = "GS290_MEGASUITE_TMP";
        RecordStore store = null;
        try {
            store = RecordStore.openRecordStore(name, true);
            byte[] src = new byte[] {71, 83, 50, 57, 48, 1, 2, 3};
            int id = store.addRecord(src, 0, src.length);
            byte[] got = store.getRecord(id);
            boolean equal = got.length == src.length;
            for (int i = 0; equal && i < src.length; i++) equal = got[i] == src[i];
            check("RMS create/read", equal, "recordId=" + id
                    + " length=" + got.length);
            src[7] = 99;
            store.setRecord(id, src, 0, src.length);
            check("RMS update", store.getRecord(id)[7] == 99,
                  "read_after_update=" + store.getRecord(id)[7]);
            store.deleteRecord(id);
            check("RMS delete record", store.getNumRecords() == 0,
                  "count=" + store.getNumRecords());
        } catch (Throwable e) {
            item("FAIL", "RMS transaction", error(e));
        } finally {
            if (store != null) {
                try { store.closeRecordStore(); } catch (Throwable ignored) { }
            }
            try { RecordStore.deleteRecordStore(name); } catch (Throwable ignored) { }
        }
    }
    private void testFilesystem() {
        try {
            String[] roots = ReportFileWriter.roots();
            item(roots.length > 0 ? "PASS" : "N/A",
                 "JSR-75 roots", "count=" + roots.length);
            for (int i = 0; i < roots.length && i < 12; i++) {
                report.append("  ROOT ").append(i).append(": ").append(roots[i]).append("\r\n");
            }
            report.append("  No file writing performed by inventory test.\r\n");
        } catch (Throwable e) {
            item("N/A", "JSR-75 roots", error(e));
        }
    }
}
