package net.lshift.spki.convert;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;

/**
 * Convert TResult to SExp by first converting it to TStep using stepIn/stepOut
 */
public abstract class StepConverter<TResult, TStep>
        extends ConverterImpl<TResult> {

    protected final Class<TStep> stepClazz;

    public StepConverter(final Class<TResult> clazz, final Class<TStep> stepClazz) {
        super(clazz);
        this.stepClazz = stepClazz;
    }

    @Override
    public Sexp write(final TResult o) {
        return writeUnchecked(stepClazz, stepIn(o));
    }

    @Override
    public TResult read(final ConverterCatalog c, final Sexp in)
        throws InvalidInputException {
        return stepOut(readElement(stepClazz, c, in));
    }

    protected abstract TResult stepOut(TStep s) throws InvalidInputException;

    protected abstract TStep stepIn(TResult o);

}
