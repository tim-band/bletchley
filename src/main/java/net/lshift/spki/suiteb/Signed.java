package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;

@Convert.ByPosition(name="signed", fields={"hashType", "payload"})
public class Signed implements SequenceItem {
    public final String hashType;
    public final SequenceItem payload;

    public Signed(String hashType, SequenceItem payload) {
        super();
        this.hashType = hashType;
        this.payload = payload;
    }

    public static Signed signed(SequenceItem payload) {
        return new Signed(DigestSha384.DIGEST_NAME, payload);
    }
}
