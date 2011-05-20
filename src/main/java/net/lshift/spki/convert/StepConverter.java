package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.Sexp;

/**
 * Convert TResult to SExp by first converting it to TStep using stepIn/stepOut
 */
public abstract class StepConverter<TResult, TStep>
    implements Converter<TResult>
{
    @Override
    public TResult fromSexp(Sexp sexp)
    {
        return stepOut(Convert.fromSExp(getStepClass(), sexp));
    }

    @Override
    public void write(ConvertOutputStream out, TResult o)
        throws IOException
    {
        out.write(getStepClass(), stepIn(o));
    }

    public void registerSelf()
    {
        Convert.REGISTRY.register(getResultClass(), this);
    }

    protected abstract Class<TResult> getResultClass();

    protected abstract Class<TStep> getStepClass();

    protected abstract TResult stepOut(TStep fromSExp);

    protected abstract TStep stepIn(TResult o);
}
