package net.lshift.spki.suiteb;

import java.util.Arrays;

import net.lshift.spki.Marshal;
import net.lshift.spki.SExp;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.PackConvertable;
import net.lshift.spki.suiteb.sexpstructs.Hash;

import org.bouncycastle.crypto.digests.SHA384Digest;

/**
 * A SHA-384 digest of a SExp.
 */
public class DigestSha384 extends PackConvertable
{
    private static final String DIGEST_NAME = "sha384";
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

    @Override
    public Hash pack()
    {
        return new Hash(DIGEST_NAME, bytes);
    }

    public static DigestSha384 unpack(Hash hash) {
        if (!DIGEST_NAME.equals(hash.hashType)) {
            throw new ConvertException("Unexpected hash type: " + hash.hashType);
        }
        return new DigestSha384(hash.value);
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

    public static <T> DigestSha384 digest(Class<T> clazz, T o)
    {
        return digest(Convert.toSExp(clazz, o));
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DigestSha384 other = (DigestSha384) obj;
        if (!Arrays.equals(bytes, other.bytes)) return false;
        return true;
    }
}
