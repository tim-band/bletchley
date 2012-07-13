package net.lshift.spki.suiteb.simplemessage;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;
import net.lshift.spki.suiteb.ActionType;

/**
 * Format for a simple kind of message - just identifier and data - that
 * can be encrypted and/or signed.
 */
@Convert.ByPosition(name="simple-message", fields={"type", "content"})
public class SimpleMessage extends SexpBacked implements ActionType {
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
}
