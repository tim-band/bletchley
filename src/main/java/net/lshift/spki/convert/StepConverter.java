package net.lshift.spki.convert;

import java.util.Collections;
import java.util.Set;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.schema.ConverterDeclaration;
import net.lshift.spki.schema.Restriction;
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

    @Override
    public ConverterDeclaration declaration() {
        return new Restriction(stepClazz);
    }

    @Override
    public Set<Class<?>> references() {
        return Collections.<Class<?>>singleton(stepClazz);
    }
}
