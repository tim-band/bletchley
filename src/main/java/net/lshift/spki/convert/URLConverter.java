package net.lshift.spki.convert;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Serialize URLs as strings
 */
public class URLConverter
    extends StringStepConverter<URL>
{
    @Override public Class<URL> getResultClass() { return URL.class; }

    @Override
    protected String stepIn(final URL o) { return o.toString(); }

    @Override
    protected URL stepOut(final String s) throws ConvertException {
        try {
            return new URL(s);
        } catch (final MalformedURLException e) {
            throw new ConvertException(e);
        }
    }
}
