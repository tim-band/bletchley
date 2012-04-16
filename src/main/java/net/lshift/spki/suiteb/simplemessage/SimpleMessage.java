package net.lshift.spki.suiteb.simplemessage;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.ActionType;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Format for a simple kind of message - just identifier and data - that
 * can be encrypted and/or signed.
 */
@Convert.ByPosition(name="simple-message", fields={"type", "content"})
@Convert.InstanceOf(ActionType.class)
public class SimpleMessage implements ActionType {
    public final String type;
    public final byte[] content;

    public SimpleMessage(
        final String type,
        final byte[] content
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
    public boolean equals(final Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }
}
