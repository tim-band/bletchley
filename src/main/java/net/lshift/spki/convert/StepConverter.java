package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

/**
 * Convert TResult to SExp by first converting it to TStep using stepIn/stepOut
 */
public abstract class StepConverter<TResult, TStep>
    extends ConverterImpl<TResult> {

    public StepConverter(final Class<TResult> clazz) {
        super(clazz);
    }

    @Override
    public Sexp write(final TResult o) {
        return writeUnchecked(getStepClass(), stepIn(o));
    }

    @Override
    public TResult read(final ReadInfo c, final Sexp in)
        throws InvalidInputException {
        TResult res = stepOut(readElement(getStepClass(), c, in));
        if (SexpBacked.class.isAssignableFrom(clazz)) {
            ((SexpBacked)res).setSexp(in);
        }
        return res;
    }

    protected abstract Class<TStep> getStepClass();

    protected abstract TResult stepOut(TStep s) throws InvalidInputException;

    protected abstract TStep stepIn(TResult o);
}
