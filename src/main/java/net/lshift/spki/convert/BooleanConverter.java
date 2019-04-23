package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;

public class BooleanConverter
        extends StepConverter<Boolean, String> {

    public BooleanConverter() {
        super(Boolean.class, String.class);
    }

    @Override
    protected String stepIn(Boolean s) {
        return s.toString();
    }

    @Override
    protected Boolean stepOut(String o) throws InvalidInputException {
        switch(o) {
            case "true": return true;
            case "false": return false;
            default: throw new InvalidInputException(o);
        }
    }
}
