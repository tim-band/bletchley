package net.lshift.spki.convert;

import java.util.UUID;

/**
 * Serialize/deserialize a UUID
 */
public class UUIDConverter
    extends StepConverter<UUID, String>
{
    @Override
    public Class<UUID> getResultClass() { return UUID.class; }

    @Override
    protected Class<String> getStepClass() { return String.class; }

    @Override
    protected String stepIn(final UUID o) { return o.toString(); }

    @Override
    protected UUID stepOut(final String s) { return UUID.fromString(s); }
}
