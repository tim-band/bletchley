package net.lshift.spki.suiteb;

import net.lshift.spki.InvalidInputException;

/**
 * Thrown if input fails some cryptographic test, eg a signature is
 * invalid or a MAC doesn't check out. This should NOT be thrown if eg
 * a signature is valid but we don't trust the signer.
 */
public class CryptographyException
    extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public CryptographyException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public CryptographyException(final String message) {
        super(message);
    }

    public CryptographyException(final Throwable cause) {
        super(cause);
    }
}
