package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

/**
 * SPKI hash value format
 */
@Convert.ByPosition(name = "hash", fields={"hashType", "value"})
public class Hash extends SexpBacked {
    public final String hashType;
    public final byte[] value;

    public Hash(
        final String hashType,
        final byte[] value
    ) {
        super();
        this.hashType = hashType;
        this.value = value;
    }
}
