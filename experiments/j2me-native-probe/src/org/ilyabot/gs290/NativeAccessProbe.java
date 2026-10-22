package org.ilyabot.gs290;

import java.io.InputStream;
import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;

/**
 * Instrumented Java ME loader probe for the owner's LG GS290.
 *
 * Normal Java has no arbitrary ARM register or memory access. The optional
 * alternate JAR merely asks the VM to inflate a deliberately malformed
 * resource. Even a restart after that probe is NOT proof of native execution.
 */
public final class NativeAccessProbe extends MIDlet implements CommandListener {
    private static final String RMS_NAME = "GS290_NATIVE_PROBE";
    private static final String RESOURCE = "/GS290ProbePayload.bin";
    private static final Command CMD_JAVA = new Command("Java APIs", Command.SCREEN, 1);
    private static final Command CMD_INFLATE = new Command("DEFLATE test", Command.SCREEN, 2);
    private static final Command CMD_EXIT = new Command("Exit", Command.EXIT, 3);

    private Display display;
    private Screen screen;
    private String vm = "?";
    private String profile = "?";
    private String platform = "?";
    private String last = "NOT RUN";
    private String javaStatus = "NOT RUN";
    private String streamStatus = "NOT RUN";
    private String prior = "NONE";
    private boolean tested;

    public void startApp() {
        if (display == null) {
            display = Display.getDisplay(this);
            vm = prop("microedition.configuration");
            profile = prop("microedition.profiles");
            platform = prop("microedition.platform");
            prior = readMarker();
            screen = new Screen();
            screen.addCommand(CMD_JAVA);
            screen.addCommand(CMD_INFLATE);
            screen.addCommand(CMD_EXIT);
            screen.setCommandListener(this);
        }
        display.setCurrent(screen);
    }

    public void pauseApp() { }
    public void destroyApp(boolean unconditional) { }

    private static String prop(String key) {
        try {
            String value = System.getProperty(key);
            return value == null ? "(unset)" : value;
        } catch (Throwable ex) {
            return "ERROR " + ex.getClass().getName();
        }
    }

    private static boolean exists(String cls) {
        try {
            Class.forName(cls);
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }

    private void runJavaChecks() {
        // Class presence only: neither privilege, register reads, nor exploit.
        boolean unsafe = exists("sun.misc.Unsafe");
        boolean fileApi = exists("javax.microedition.io.file.FileConnection");
        boolean lgGraphics = exists("com.lge.lcdui.LGCanvas");
        javaStatus = "Unsafe=" + (unsafe ? "FOUND" : "NO")
                + " FileAPI=" + (fileApi ? "YES" : "NO")
                + " LGCanvas=" + (lgGraphics ? "YES" : "NO");
        last = "JAVA API SCAN COMPLETED";
        screen.repaint();
    }

    private void runInflateProbe() {
        // Arm the persistent marker before invoking the firmware ZIP inflater.
        // If the native Java process crashes, next launch can show ARMED.
        writeMarker("ARMED");
        streamStatus = "ARMED; OPENING ZIP ENTRY";
        last = "RUNNING RESOURCE READ";
        screen.repaint();
        InputStream stream = null;
        try {
            stream = getClass().getResourceAsStream(RESOURCE);
            if (stream == null) {
                streamStatus = "RESOURCE MISSING";
            } else {
                byte[] buf = new byte[128];
                int n;
                int bytes = 0;
                int sum = 0;
                while (bytes < 4096 && (n = stream.read(buf)) >= 0) {
                    for (int i = 0; i < n; i++) sum = (sum + (buf[i] & 255)) & 0xffff;
                    bytes += n;
                    if (n == 0) break;
                }
                streamStatus = "RETURNED bytes=" + bytes + " sum=" + sum;
            }
            last = "INFLATE RETURNED (NOT RCE)";
        } catch (Throwable ex) {
            String label = ex.getClass().getName();
            streamStatus = "ERROR " + label;
            last = "INFLATE EXCEPTION (NOT RCE)";
        } finally {
            if (stream != null) {
                try { stream.close(); } catch (Throwable ignored) { }
            }
            // If this line executes, the Java thread returned from the read.
            writeMarker("FINISHED");
            tested = true;
            screen.repaint();
        }
    }

    private static void writeMarker(String value) {
        RecordStore rs = null;
        try {
            rs = RecordStore.openRecordStore(RMS_NAME, true);
            byte[] b = value.getBytes("UTF-8");
            if (rs.getNumRecords() == 0) rs.addRecord(b, 0, b.length);
            else rs.setRecord(1, b, 0, b.length);
        } catch (Throwable ignored) { }
        finally {
            if (rs != null) try { rs.closeRecordStore(); } catch (Throwable ignored) { }
        }
    }

    private static String readMarker() {
        RecordStore rs = null;
        try {
            rs = RecordStore.openRecordStore(RMS_NAME, true);
            if (rs.getNumRecords() == 0) return "NONE";
            byte[] b = rs.getRecord(1);
            return new String(b, "UTF-8");
        } catch (Throwable ex) {
            return "RMS ERROR";
        } finally {
            if (rs != null) try { rs.closeRecordStore(); } catch (Throwable ignored) { }
        }
    }

    public void commandAction(Command c, Displayable d) {
        if (c == CMD_EXIT) notifyDestroyed();
        else if (c == CMD_JAVA) runJavaChecks();
        else if (c == CMD_INFLATE) runInflateProbe();
    }

    private final class Screen extends Canvas {
        private final Font f = Font.getFont(Font.FACE_MONOSPACE, Font.STYLE_PLAIN, Font.SIZE_SMALL);
        protected void paint(Graphics g) {
            int w = getWidth(), h = getHeight();
            g.setColor(0x000000);
            g.fillRect(0, 0, w, h);
            g.setFont(f);
            g.setColor(0xffffff);
            int y = 3;
            y = line(g, "LG GS290 / AROMA PROBE", 4, y, 18);
            g.drawLine(4, y, w - 4, y); y += 6;
            y = line(g, "CLDC: " + vm, 4, y, 18);
            y = line(g, "MIDP: " + profile, 4, y, 18);
            y = line(g, "PLATFORM: " + clip(platform, 25), 4, y, 18);
            y = line(g, "SCREEN: " + w + "x" + h, 4, y, 18);
            y = line(g, "LAST RMS: " + prior, 4, y, 18);
            g.setColor(0xaaaaaa);
            y = line(g, "JAVA: " + clip(javaStatus, 28), 4, y, 18);
            y = line(g, "ZIP: " + clip(streamStatus, 28), 4, y, 18);
            y = line(g, clip(last, 28), 4, y, 18);
            g.setColor(0xffffff);
            y += 2;
            g.drawLine(4, y, w - 4, y); y += 8;
            y = line(g, "ARM REGISTERS: NO API", 4, y, 18);
            y = line(g, "RAW MEMORY: NO API", 4, y, 18);
            y = line(g, "NATIVE EXEC: UNPROVEN", 4, y, 18);
            if (prior.equals("ARMED") && !tested) {
                g.setColor(0xffff00);
                line(g, "PREVIOUS RUN INTERRUPTED", 4, y, 18);
            }
        }
        private int line(Graphics g, String s, int x, int y, int dy) {
            g.drawString(clip(s, 32), x, y, Graphics.TOP | Graphics.LEFT);
            return y + dy;
        }
        private String clip(String s, int max) {
            return s.length() > max ? s.substring(0, max) : s;
        }
    }
}
