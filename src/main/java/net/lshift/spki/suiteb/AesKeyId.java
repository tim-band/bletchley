package net.lshift.spki.suiteb;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import com.google.protobuf.ByteString;

/**
 * Identifier for a symmetric key, deterministically generated from the key.
 * Symmetrically encrypted packets carry this information so you know what
 * key to decrypt them with.
 */
public final class AesKeyId {
    public final byte[] keyId;

    public AesKeyId(final byte[] keyId) {
        this.keyId = keyId;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyId);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        return Arrays.equals(keyId, ((AesKeyId) obj).keyId);
    }

    public ByteString toProtobuf() {
        return ByteString.copyFrom(keyId);
    }
    
    public String toString() {
        return new String(Hex.encode(keyId));
    }
}
