package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;

/**
 * SPKI hash value format
 */
@Convert.ByPosition(name = "hash", fields={"hashType", "value"})
public class Hash {
    public final String hashType;
    public final byte[] value;

    public Hash(
        String hashType,
        byte[] value
    ) {
        super();
        this.hashType = hashType;
        this.value = value;
    }
}
