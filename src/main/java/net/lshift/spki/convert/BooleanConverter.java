package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;

public class BooleanConverter
    extends StepConverter<Boolean, BooleanEnum>
{
    public BooleanConverter() { super(Boolean.class); }

    @Override
    protected Class<BooleanEnum> getStepClass() {
        return BooleanEnum.class;
    }

    @Override
    public Class<Boolean> getResultClass() {
        return Boolean.class;
    }

    @Override
    protected BooleanEnum stepIn(Boolean s) {
        return s ? BooleanEnum.TRUE : BooleanEnum.FALSE;
    }

    @Override
    protected Boolean stepOut(BooleanEnum o) throws InvalidInputException {
        switch(o) {
        case TRUE: return true;
        case FALSE: return false;
        default: throw new InvalidInputException(o.name());
        }
    }

}
