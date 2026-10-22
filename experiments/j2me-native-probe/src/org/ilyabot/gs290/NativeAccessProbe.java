package org.ilyabot.gs290;

import java.io.InputStream;
import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.AlertType;
import javax.microedition.lcdui.Choice;
import javax.microedition.lcdui.ChoiceGroup;
import javax.microedition.lcdui.Form;
import javax.microedition.lcdui.TextField;
import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;
import java.util.Vector;

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
    private static final Command CMD_ALL = new Command("Run ALL", Command.SCREEN, 1);
    private static final Command CMD_SAVE = new Command("Save TXT", Command.SCREEN, 3);
    private static final Command CMD_WRITE = new Command("Save", Command.OK, 1);
    private static final Command CMD_CANCEL = new Command("Cancel", Command.BACK, 2);
    private static final Command CMD_EXIT = new Command("Exit", Command.EXIT, 4);

    private Display display;
    private Screen screen;
    private String vm = "?";
    private String profile = "?";
    private String platform = "?";
    private String last = "NOT RUN";
    private String javaStatus = "NOT RUN";
    private String streamStatus = "NOT RUN";
    private String prior = "NONE";
    private String saveStatus = "NOT SAVED";
    private String suiteStatus = "NOT RUN";
    private String megaReport = "";
    private boolean suiteRunning;
    private int suiteRunCount;
    private Form exportForm;
    private ChoiceGroup exportRoots;
    private TextField exportFilename;
    private String[] detectedRoots;
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
            screen.addCommand(CMD_ALL);
            screen.addCommand(CMD_SAVE);
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

    private String buildReport() {
        StringBuffer b = new StringBuffer(800);
        b.append("GS290 NATIVE ACCESS PROBE REPORT\r\n");
        b.append("Version: 0.2.0\r\n");
        b.append("Timestamp (epoch ms): ").append(System.currentTimeMillis()).append("\r\n");
        b.append("MIDlet: GS290 Native Probe / IlyaBOT\r\n");
        b.append("CLDC: ").append(vm).append("\r\n");
        b.append("MIDP: ").append(profile).append("\r\n");
        b.append("Platform: ").append(platform).append("\r\n");
        b.append("Canvas size: ").append(screen.getWidth()).append("x")
            .append(screen.getHeight()).append("\r\n");
        b.append("FileConnection API: ")
            .append(prop("microedition.io.file.FileConnection.version")).append("\r\n");
        b.append("Java heap free: ").append(Runtime.getRuntime().freeMemory()).append("\r\n");
        b.append("Java heap total: ").append(Runtime.getRuntime().totalMemory()).append("\r\n");
        b.append("\r\nRESULTS\r\n");
        b.append("Previous RMS marker: ").append(prior).append("\r\n");
        b.append("Current RMS marker: ").append(readMarker()).append("\r\n");
        b.append("Java class checks: ").append(javaStatus).append("\r\n");
        b.append("DEFLATE result: ").append(streamStatus).append("\r\n");
        b.append("Last operation: ").append(last).append("\r\n");
        b.append("\r\nLIMITATIONS\r\n");
        b.append("ARM registers: unavailable from standard Java ME\r\n");
        b.append("Arbitrary memory: unavailable from standard Java ME\r\n");
        b.append("Native execution: NOT PROVEN\r\n");
        b.append("RMS interruption is not evidence of RCE.\r\n");
        b.append("Malformed DEFLATE experiments are excluded from control builds.\r\n");
        b.append("\r\nMEGASUITE SUMMARY\r\n");
        b.append("Status: ").append(suiteStatus).append("\r\n");
        if (megaReport.length() > 0) b.append(megaReport);
        return b.toString();
    }

    private void startMegaSuite() {
        if (suiteRunning) return;
        suiteRunning = true;
        suiteRunCount++;
        suiteStatus = "RUNNING # " + suiteRunCount;
        megaReport = "";
        writeMarker("MEGA:RUNNING");
        screen.repaint();
        Thread worker = new Thread(new Runnable() {
            public void run() {
                String outcome = "SUITE FAILED";
                try {
                    MegaSuite suite = new MegaSuite(NativeAccessProbe.this,
                            NativeAccessProbe.class, new MegaSuite.Progress() {
                        public void onProgress(String msg) {
                            suiteStatus = msg;
                            screen.repaint();
                        }
                    });
                    megaReport = suite.execute();
                    outcome = "FINISHED; " + megaReport.length() + " chars";
                    writeMarker("MEGA:FINISHED");
                } catch (Throwable ex) {
                    megaReport += "\r\n[FATAL] " + ex.getClass().getName() +
                            " " + ex.getMessage() + "\r\n";
                    outcome = "FAILED: " + ex.getClass().getName();
                    writeMarker("MEGA:FAILED");
                } finally {
                    suiteStatus = outcome;
                    suiteRunning = false;
                    last = "MEGASUITE " + outcome;
                    try {
                        // Best effort auto-export. If permission is denied,
                        // manual Save TXT remains available.
                        String[] roots = ReportFileWriter.roots();
                        if (roots.length > 0) {
                            String name = "GS290_Mega_" +
                                  (System.currentTimeMillis() % 10000000L) + ".txt";
                            String saved = ReportFileWriter.writeNew(
                                    roots[0], name, buildReport());
                            saveStatus = "AUTO: " + saved;
                        } else {
                            saveStatus = "NO AUTO SAVE ROOT; USE Save TXT";
                        }
                    } catch (Throwable saveError) {
                        saveStatus = "AUTO SAVE FAILED: " + saveError.getClass().getName()
                                + " (use Save TXT)";
                    }
                    screen.repaint();
                }
            }
        });
        worker.start();
    }

    private void showExportForm() {
        // JSR-75 FileConnection is optional on MIDP devices.
        if (!exists("javax.microedition.io.file.FileConnection")) {
            saveStatus = "JSR-75 FILE API NOT AVAILABLE";
            showAlert("TXT export", saveStatus, AlertType.WARNING);
            return;
        }
        try {
            detectedRoots = ReportFileWriter.roots();
            if (detectedRoots.length == 0) {
                saveStatus = "NO FILESYSTEM ROOTS";
                showAlert("TXT export", saveStatus, AlertType.WARNING);
                return;
            }
            exportForm = new Form("Save debug report");
            exportRoots = new ChoiceGroup("Storage", Choice.EXCLUSIVE);
            for (int i = 0; i < detectedRoots.length; i++) {
                exportRoots.append(detectedRoots[i], null);
            }
            exportRoots.setSelectedIndex(0, true);
            String filename = "GS290_Report_" +
                              (System.currentTimeMillis() % 10000000L) + ".txt";
            exportFilename = new TextField("File name", filename, 50, TextField.ANY);
            exportForm.append(exportRoots);
            exportForm.append(exportFilename);
            exportForm.append("Uses JSR-75 FileConnection; the phone may request permission. Existing files are never overwritten.");
            exportForm.addCommand(CMD_WRITE);
            exportForm.addCommand(CMD_CANCEL);
            exportForm.setCommandListener(this);
            display.setCurrent(exportForm);
        } catch (SecurityException e) {
            saveStatus = "DENIED: " + e.getClass().getName();
            showAlert("TXT export", saveStatus, AlertType.ERROR);
        } catch (Throwable e) {
            saveStatus = "ROOT ERROR: " + e.getClass().getName() + " " + e.getMessage();
            showAlert("TXT export", saveStatus, AlertType.ERROR);
        }
    }

    private void writeExport() {
        try {
            int index = exportRoots.getSelectedIndex();
            if (index < 0 || index >= detectedRoots.length) {
                throw new IllegalArgumentException("Select storage root");
            }
            String filename = exportFilename.getString();
            String location = ReportFileWriter.writeNew(
                    detectedRoots[index], filename, buildReport());
            saveStatus = "SAVED: " + location;
            last = "TXT REPORT SAVED";
            showAlert("TXT saved", location, AlertType.INFO);
        } catch (SecurityException ex) {
            saveStatus = "PERMISSION DENIED: " + ex.getClass().getName();
            last = "TXT SAVE DENIED";
            showAlert("TXT export failed", saveStatus, AlertType.ERROR);
        } catch (Throwable ex) {
            saveStatus = "SAVE ERROR: " + ex.getClass().getName() + ": " + ex.getMessage();
            last = "TXT SAVE FAILED";
            showAlert("TXT export failed", saveStatus, AlertType.ERROR);
        }
        screen.repaint();
    }

    private void showAlert(String title, String value, AlertType type) {
        Alert alert = new Alert(title, value, null, type);
        alert.setTimeout(Alert.FOREVER);
        display.setCurrent(alert, screen);
    }

    public void commandAction(Command c, Displayable d) {
        if (c == CMD_EXIT) notifyDestroyed();
        else if (c == CMD_JAVA) runJavaChecks();
        else if (c == CMD_INFLATE) runInflateProbe();
        else if (c == CMD_SAVE) showExportForm();
        else if (c == CMD_ALL) startMegaSuite();
        else if (c == CMD_WRITE && d == exportForm) writeExport();
        else if (c == CMD_CANCEL && d == exportForm) display.setCurrent(screen);
    }

    /**
     * Small-screen text view: word wrap by actual font pixel width, not by a
     * fixed character count. Supports touchscreen drags and 2/8 or up/down.
     */
    private final class Screen extends Canvas {
        private final Font f = Font.getFont(Font.FACE_MONOSPACE, Font.STYLE_PLAIN,
                                            Font.SIZE_SMALL);
        private final int lineHeight = f.getHeight() + 3;
        private int scrollY = 0;
        private int maxScroll = 0;
        private int touchStartY = 0;
        private int touchStartScroll = 0;
        private boolean touchMoved = false;

        private void appendWrapped(Vector lines, String text, int width) {
            // Also honor explicit line breaks if the diagnostic text has any.
            int offset = 0;
            while (offset <= text.length()) {
                int next = text.indexOf('\n', offset);
                if (next < 0) next = text.length();
                String section = text.substring(offset, next);
                if (section.length() == 0) {
                    lines.addElement("");
                } else {
                    int pos = 0;
                    while (pos < section.length()) {
                        while (pos < section.length() && section.charAt(pos) == ' ') pos++;
                        if (pos >= section.length()) break;
                        int fit = pos;
                        int lastSpace = -1;
                        for (int i = pos + 1; i <= section.length(); i++) {
                            if (f.stringWidth(section.substring(pos, i)) > width) break;
                            fit = i;
                            if (i < section.length() && section.charAt(i) == ' ') {
                                lastSpace = i;
                            }
                        }
                        // Split a long single token at the character boundary.
                        if (fit == pos) fit = pos + 1;
                        if (fit < section.length() && lastSpace > pos) fit = lastSpace;
                        lines.addElement(section.substring(pos, fit));
                        pos = fit;
                    }
                }
                if (next == text.length()) break;
                offset = next + 1;
            }
        }

        private Vector makeLines(int width, int height) {
            Vector lines = new Vector();
            int maxWidth = Math.max(24, width - 18);
            appendWrapped(lines, "LG GS290 / MEGASUITE v0.2.0", maxWidth);
            lines.addElement("");
            appendWrapped(lines, "CLDC: " + vm, maxWidth);
            appendWrapped(lines, "MIDP: " + profile, maxWidth);
            appendWrapped(lines, "PLATFORM: " + platform, maxWidth);
            appendWrapped(lines, "SCREEN: " + width + "x" + height, maxWidth);
            appendWrapped(lines, "LAST RMS: " + prior, maxWidth);
            lines.addElement("");
            appendWrapped(lines, "JAVA: " + javaStatus, maxWidth);
            appendWrapped(lines, "ZIP: " + streamStatus, maxWidth);
            appendWrapped(lines, last, maxWidth);
            appendWrapped(lines, "TXT: " + saveStatus, maxWidth);
            appendWrapped(lines, "RUN ALL: " + suiteStatus, maxWidth);
            lines.addElement("");
            appendWrapped(lines, "ARM REGISTERS: NO API", maxWidth);
            appendWrapped(lines, "RAW MEMORY: NO API", maxWidth);
            appendWrapped(lines, "NATIVE EXEC: UNPROVEN", maxWidth);
            if ((prior.equals("ARMED") || prior.equals("MEGA:RUNNING")) && !tested) {
                lines.addElement("");
                appendWrapped(lines, "PREVIOUS RUN INTERRUPTED", maxWidth);
            }
            lines.addElement("");
            appendWrapped(lines, "SCROLL: swipe / UP-DOWN / 2-8", maxWidth);
            return lines;
        }

        protected void paint(Graphics g) {
            int width = getWidth();
            int height = getHeight();
            g.setColor(0x000000);
            g.fillRect(0, 0, width, height);
            g.setFont(f);

            Vector lines = makeLines(width, height);
            int totalHeight = 8 + lines.size() * lineHeight;
            maxScroll = Math.max(0, totalHeight - height);
            scrollY = Math.min(Math.max(scrollY, 0), maxScroll);

            // Only render visible lines. Clipping keeps scrolling fast on
            // memory-constrained devices and preserves system softkeys.
            int top = 4 - scrollY;
            g.setClip(0, 0, width, height);
            g.setColor(0xffffff);
            for (int i = 0; i < lines.size(); i++) {
                int y = top + i * lineHeight;
                if (y + lineHeight <= 0 || y >= height) continue;
                String line = (String) lines.elementAt(i);
                if (line.length() != 0) {
                    g.drawString(line, 4, y, Graphics.TOP | Graphics.LEFT);
                }
            }
            if (maxScroll > 0) {
                // Narrow scrollbar: size and thumb position proportional
                // to the actual document and viewport heights.
                int barX = width - 4;
                int thumbHeight = Math.max(12, height * height / totalHeight);
                thumbHeight = Math.min(thumbHeight, height);
                int thumbY = scrollY * (height - thumbHeight) / maxScroll;
                g.setColor(0x444444);
                g.fillRect(barX, 0, 3, height);
                g.setColor(0xffffff);
                g.fillRect(barX, thumbY, 3, thumbHeight);
            }
        }

        private void scrollBy(int pixels) {
            int next = Math.max(0, Math.min(maxScroll, scrollY + pixels));
            if (next != scrollY) {
                scrollY = next;
                repaint();
            }
        }

        protected void keyPressed(int keyCode) {
            int action = 0;
            try {
                action = getGameAction(keyCode);
            } catch (IllegalArgumentException ignored) { }
            if (action == Canvas.UP || keyCode == Canvas.KEY_NUM2) {
                scrollBy(-lineHeight * 3);
            } else if (action == Canvas.DOWN || keyCode == Canvas.KEY_NUM8) {
                scrollBy(lineHeight * 3);
            }
        }

        protected void keyRepeated(int keyCode) {
            keyPressed(keyCode);
        }

        protected void pointerPressed(int x, int y) {
            touchStartY = y;
            touchStartScroll = scrollY;
            touchMoved = false;
        }

        protected void pointerDragged(int x, int y) {
            if (Math.abs(y - touchStartY) >= 3) touchMoved = true;
            int next = Math.max(0, Math.min(maxScroll,
                                           touchStartScroll + touchStartY - y));
            if (next != scrollY) {
                scrollY = next;
                repaint();
            }
        }

        protected void pointerReleased(int x, int y) {
            int delta = touchStartY - y;
            if (Math.abs(delta) >= 6) {
                int next = Math.max(0, Math.min(maxScroll, touchStartScroll + delta));
                if (next != scrollY) {
                    scrollY = next;
                    repaint();
                }
            } else if (!touchMoved) {
                // Some MIDP touch implementations deliver press/release but
                // never send pointerDragged; tap halves as a fallback.
                scrollBy((y > getHeight() / 2 ? 1 : -1) * lineHeight * 3);
            }
        }
    }
}
