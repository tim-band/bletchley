package net.lshift.spki.convert;

import static java.lang.String.format;

import java.util.UUID;
import java.util.regex.Pattern;

import net.lshift.spki.InvalidInputException;

/**
 * Serialize/deserialize a UUID
 */
public class UUIDConverter
    extends StringStepConverter<UUID>
{
    public static final String UUID_PART = "([0-9a-f]{%1$d})";
    public static final int [] UUID_PART_LENGTHS = { 8, 4, 4, 4, 12 };

    public static final Pattern UUID_PATTERN = Pattern.compile(
        format("%s-%s-%s-%s-%s",
            format(UUID_PART, 8),
            format(UUID_PART, 4),
            format(UUID_PART, 4),
            format(UUID_PART, 4),
            format(UUID_PART, 12)));

    @Override public Class<UUID> getResultClass() { return UUID.class; }

    @Override
    protected String stepIn(final UUID o) { return o.toString().toLowerCase(); }

    @Override
    protected UUID stepOut(final String s) throws InvalidInputException { 
        if(!validUUID(s))
            throw new InvalidInputException(s);
        return UUID.fromString(s); 
    }

    /** 
     * Validate a UUID.
     * At least in Java 6, UUID#fromString is rubbish: it splits
     * the string on '-', checks the number of segments is 5, and then
     * blindly Long#decodes them, so there are lots of ways of
     * producing the same UUID. We need to check the UUID against
     * a stricter pattern.
     */
    public static boolean validUUID(final String s) {
        return UUID_PATTERN.matcher(s).matches();
    }
}
