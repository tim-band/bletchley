package net.lshift.spki.convert;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Serialize URIs as strings.
 */
public class URIConverter
    extends StringStepConverter<URI>
{
    public URIConverter() { super(URI.class); }

    @Override
    protected URI stepOut(final String s) throws ConvertException {
        try {
            return new URI(s);
        } catch (final URISyntaxException e) {
            throw new ConvertException(e);
        }
    }

    @Override
    protected String stepIn(final URI o) {
        return o.toString();
    }
}
