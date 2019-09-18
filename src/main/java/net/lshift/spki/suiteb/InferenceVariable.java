package net.lshift.spki.suiteb;

import java.util.Random;

public final class InferenceVariable<T> {
    private static final Random random = new Random();

    private final Class<?> type;
    private final String name;
    private final long v1 = random.nextLong();
    private final long v2 = random.nextLong();

    public InferenceVariable(final Class<?> type, final String name) {
        this.type = type;
        this.name = name;
    }

    @SuppressWarnings("unchecked")
    public T get(final InferenceEngine engine) {
        return (T) engine.getVar(this);
    }

    public void set(final InferenceEngine engine, final T o) {
        engine.setVar(this, o);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + (int) (v1 ^ (v1 >>> 32));
        result = prime * result + (int) (v2 ^ (v2 >>> 32));
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        @SuppressWarnings("rawtypes")
        final InferenceVariable other = (InferenceVariable) obj;
        if (name == null) {
            if (other.name != null) return false;
        } else if (!name.equals(other.name)) return false;
        if (type == null) {
            if (other.type != null) return false;
        } else if (!type.equals(other.type)) return false;
        if (v1 != other.v1) return false;
        if (v2 != other.v2) return false;
        return true;
    }

    @Override
    public String toString() {
        return "InferenceVariable [type=" + type + ", name=" + name + "]";
    }
}
