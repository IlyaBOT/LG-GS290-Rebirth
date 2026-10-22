package org.ilyabot.gs290;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Vector;
import javax.microedition.io.Connector;
import javax.microedition.io.file.FileConnection;
import javax.microedition.io.file.FileSystemRegistry;

/**
 * JSR-75 FileConnection extension, kept separate from the MIDlet entry class.
 * Standard Java ME API only; no manufacturer-specific native calls.
 */
public final class ReportFileWriter {
    private ReportFileWriter() { }

    public static String[] roots() throws IOException {
        Enumeration values = FileSystemRegistry.listRoots();
        Vector roots = new Vector();
        while (values.hasMoreElements()) {
            String root = (String) values.nextElement();
            if (root != null && root.length() != 0) {
                if (!root.endsWith("/")) root += "/";
                roots.addElement(root);
            }
        }
        String[] result = new String[roots.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = (String) roots.elementAt(i);
        }
        return result;
    }

    private static String validatedName(String filename) {
        if (filename == null) throw new IllegalArgumentException("Empty filename");
        filename = filename.trim();
        if (filename.length() == 0 || filename.length() > 50)
            throw new IllegalArgumentException("Filename length must be 1..50");
        for (int i = 0; i < filename.length(); i++) {
            char c = filename.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '-' || c == '.';
            if (!ok) throw new IllegalArgumentException("Use A-Z 0-9 _ - .");
        }
        if (filename.equals(".") || filename.equals(".."))
            throw new IllegalArgumentException("Invalid filename");
        if (!filename.toLowerCase().endsWith(".txt")) filename += ".txt";
        return filename;
    }

    public static String writeNew(String root, String filename, String report)
            throws IOException {
        if (root == null || root.length() == 0 || !root.endsWith("/"))
            throw new IllegalArgumentException("Invalid storage root");
        String name = validatedName(filename);
        String url = "file:///" + root + name;
        FileConnection conn = null;
        OutputStream stream = null;
        try {
            conn = (FileConnection) Connector.open(url, Connector.READ_WRITE);
            if (conn.exists()) {
                throw new IOException("File already exists. Choose another name.");
            }
            conn.create();
            stream = conn.openOutputStream();
            byte[] bytes = report.getBytes("UTF-8");
            stream.write(bytes);
            stream.flush();
            return url + " (" + bytes.length + " bytes)";
        } finally {
            if (stream != null) {
                try { stream.close(); } catch (IOException ignored) { }
            }
            if (conn != null) {
                try { conn.close(); } catch (IOException ignored) { }
            }
        }
    }
}
