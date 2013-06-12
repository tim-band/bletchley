package net.lshift.spki.convert;

public enum BooleanEnum {
    FALSE(false), TRUE(true);

    public final boolean value;

    private BooleanEnum(boolean value) {
        this.value = value;
    }
}
