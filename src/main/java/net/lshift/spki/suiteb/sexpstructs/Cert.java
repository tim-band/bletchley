package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.DigestSha384;

@Convert.ByPosition(name="cert", fields={"subject"})
public class Cert
    implements SequenceItem {
    public final DigestSha384 subject;

    public Cert(DigestSha384 subject) {
        super();
        this.subject = subject;
    }
}
