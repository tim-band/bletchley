package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert TResult to SExp by first converting it to TStep using stepIn/stepOut
 */
public abstract class StepConverter<TResult, TStep>
    implements Converter<TResult> {
    @Override
    public String getName() {
        return Registry.REGISTRY.getConverter(getStepClass()).getName();
    }

    @Override
    public void write(final ConvertOutputStream out, final TResult o)
        throws IOException {
        out.write(getStepClass(), stepIn(o));
    }

    @Override
    public TResult read(final ConvertInputStream in)
        throws ParseException,
            IOException {
        return stepOut(in.read(getStepClass()));
    }

    public abstract Class<TResult> getResultClass();

    protected abstract Class<TStep> getStepClass();

    protected abstract TResult stepOut(TStep s) throws ParseException;

    protected abstract TStep stepIn(TResult o);
}
