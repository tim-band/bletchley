package net.lshift.spki.convert;

import java.net.URI;
import java.net.URISyntaxException;

public class URIConverter
    extends StepConverter<URI, String>
{

    @Override
    public Class<URI> getResultClass() { return URI.class; }

    @Override
    protected Class<String> getStepClass() { return String.class; }

    @Override
    protected URI stepOut(String s) throws ConvertException {
        try {
            return new URI(s);
        } catch (URISyntaxException e) {
            throw new ConvertException(e);
        }
    }

    @Override
    protected String stepIn(URI o) {
        return o.toString();
    }

}
