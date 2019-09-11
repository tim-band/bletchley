package net.lshift.spki.convert;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Serialize URLs as strings
 */
public class URLConverter{
    private URLConverter() {  }

    public static String stepIn(final URL o) { return o.toString(); }

    public static URL stepOut(final String s) throws ConvertException {
        try {
            return new URL(s);
        } catch (final MalformedURLException e) {
            throw new ConvertException(e);
        }
    }
}
