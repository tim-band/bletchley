package net.lshift.spki.convert;

import java.net.MalformedURLException;
import java.net.URL;

public class URLConverter
    extends StepConverter<URL, String>
{
    @Override
    public Class<URL> getResultClass() { return URL.class; }

    @Override
    protected Class<String> getStepClass() { return String.class; }

    @Override
    protected String stepIn(final URL o) { return o.toString(); }

    @Override
    protected URL stepOut(final String s) throws ConvertException { 
        try {
            return new URL(s);
        } catch (MalformedURLException e) {
            throw new ConvertException(e);
        }
    }
}
