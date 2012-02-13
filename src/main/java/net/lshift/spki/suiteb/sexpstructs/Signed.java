package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;

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
