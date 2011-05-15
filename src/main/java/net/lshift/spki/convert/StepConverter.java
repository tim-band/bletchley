package net.lshift.spki.convert;

import net.lshift.spki.SExp;

public abstract class StepConverter<T1, T2> implements Converter<T1>
{
    @Override
    public T1 fromSexp(SExp sexp)
    {
        return stepOut(Convert.fromSExp(getStepClass(), sexp));
    }

    @Override
    public SExp toSexp(T1 o)
    {
        return Convert.toSExp(getStepClass(), stepIn(o));
    }

    public void registerSelf()
    {
        Convert.REGISTRY.register(getResultClass(), this);
    }

    protected abstract Class<T1> getResultClass();

    protected abstract Class<T2> getStepClass();

    protected abstract T1 stepOut(T2 fromSExp);

    protected abstract T2 stepIn(T1 o);
}
