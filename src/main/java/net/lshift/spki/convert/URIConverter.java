package net.lshift.spki.convert;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Serialize URIs as strings.
 */
public class URIConverter
    extends StringStepConverter<URI>
{
    @Override public Class<URI> getResultClass() { return URI.class; }

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
