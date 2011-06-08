package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Format for a simple kind of message - just identifier and data - that
 * can be encrypted and/or signed.
 */
@Convert.ByPosition(name="simple-message", fields={"type", "content"})
public class SimpleMessage implements SequenceItem {
    public final String type;
    public final byte[] content;

    public SimpleMessage(
        String type,
        byte[] content
    ) {
        super();
        this.type = type;
        this.content = content;
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }
}
