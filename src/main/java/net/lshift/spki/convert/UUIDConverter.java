package net.lshift.spki.convert;

import java.util.UUID;

import net.lshift.spki.ParseException;

public class UUIDConverter
    extends StepConverter<UUID, String>
{
    @Override
    public Class<UUID> getResultClass() { return UUID.class; }

    @Override
    protected Class<String> getStepClass() { return String.class; }

    @Override
    protected String stepIn(UUID o) {
        return o.toString();
    }

    @Override
    protected UUID stepOut(String fromSExp)
        throws ParseException {
        return UUID.fromString(fromSExp);
    }
}
