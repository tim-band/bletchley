package net.lshift.spki.convert;

import java.util.UUID;

/**
 * Serialize/deserialize a UUID
 */
public class UUIDConverter
    extends StringStepConverter<UUID>
{
    public UUIDConverter() { super(UUID.class); }

    @Override
    protected String stepIn(final UUID o) { return o.toString(); }

    @Override
    protected UUID stepOut(final String s) { return UUID.fromString(s); }
}
