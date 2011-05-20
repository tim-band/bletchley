package net.lshift.spki;

import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

/**
 * Constants useful in creating and interpreting SPKI S-expressions.
 */
public class Constants
{
    public static final Charset ASCII = Charset.forName("US-ASCII");
    public static final Charset UTF8 = Charset.forName("UTF-8");
    public static final DateFormat DATE_FORMAT;

    static {
        DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
        DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public static final byte OPENPAREN = 0x28; // '('
    public static final byte CLOSEPAREN = 0x29; // ')'
    public static final byte COLON = 0x3a; // ':'
    public static final byte DIGITBASE = 0x30; // '0'
    public static final byte OCTOTHORPE = 0x23; // '#'
    public static final byte HBAR = 0x7c; // '|'
    public static final byte DOUBLEQUOTE = 0x22; // '"'
    public static final byte BACKSLASH = 0x5c; // '\\'
    public static final byte OPENBRACE = 0x7b; // '{'
    public static final byte CLOSEBRACE = 0x7b; // '}'
}
