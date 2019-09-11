package net.lshift.spki.suiteb.sexpstructs;

/**
 * SPKI hash value format
 */
public class Hash {
    public final String hashType;
    public final byte[] value;

    public Hash(final String hashType, final byte[] value) {
        this.hashType = hashType;
        this.value = value;
    }
}
