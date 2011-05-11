package net.lshift.spki.suiteb;

import net.lshift.spki.Marshal;
import net.lshift.spki.SExp;

import org.bouncycastle.crypto.digests.SHA384Digest;

public class DigestSha384
{
    private final int DIGEST_LENGTH = 48;
    private final byte[] bytes;

    public DigestSha384(byte[] bytes)
    {
        super();
        assert bytes.length == DIGEST_LENGTH;
        this.bytes = bytes;
    }

    public byte[] getBytes()
    {
        return bytes;
    }

    public static DigestSha384 digest(SExp sexp)
    {
        // FIXME: shouldn't need to write out the whole message to digest it
        SHA384Digest digester = new SHA384Digest();
        byte[] message = Marshal.marshal(sexp);
        digester.update(message, 0, message.length);
        byte[] digest = new byte[digester.getDigestSize()];
        digester.doFinal(digest, 0);
        return new DigestSha384(digest);
    }
}
