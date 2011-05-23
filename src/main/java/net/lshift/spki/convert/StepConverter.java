package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.ParseException;

/**
 * Convert TResult to SExp by first converting it to TStep using stepIn/stepOut
 */
public abstract class StepConverter<TResult, TStep>
    implements Converter<TResult> {
    @Override
    public void write(ConvertOutputStream out, TResult o)
        throws IOException {
        out.write(getStepClass(), stepIn(o));
    }

    @Override
    public TResult read(ConvertInputStream in)
        throws ParseException,
            IOException {
        return stepOut(in.read(getStepClass()));
    }

    public void registerSelf() {
        Registry.REGISTRY.register(getResultClass(), this);
    }

    protected abstract Class<TResult> getResultClass();

    protected abstract Class<TStep> getStepClass();

    protected abstract TResult stepOut(TStep fromSExp) throws ParseException;

    protected abstract TStep stepIn(TResult o);
}
