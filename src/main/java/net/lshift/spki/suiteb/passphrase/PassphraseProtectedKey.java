package net.lshift.spki.suiteb.passphrase;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesKeyId;

@Convert.ByPosition(name="passphrase-protected-key",
    fields={"passphraseId", "salt", "iterations", "keyId"})
public class PassphraseProtectedKey {
    private final String passphraseId;
    private final byte [] salt;
    private final Integer iterations;
    private final AesKeyId keyId;

    public PassphraseProtectedKey(String passphraseId, byte[] salt,
                                  int iterations, AesKeyId keyId) {
        super();
        this.passphraseId = passphraseId;
        this.salt = salt;
        this.iterations = iterations;
        this.keyId = keyId;
    }

    public String getPassphraseId() {
        return passphraseId;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public AesKeyId getKeyId() {
        return keyId;
    }

    public AesKey getKey(String passphrase) throws InvalidInputException {
        AesKey res = PassphraseUtils.getKey(
            passphraseId, salt, iterations, passphrase);
        if (!keyId.equals(res.getKeyId())) {
            // FIXME use CryptographyException
            throw new InvalidInputException("Wrong passphrase");
        }
        return res;
    }
}
