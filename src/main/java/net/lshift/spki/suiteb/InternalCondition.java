package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto.Condition.Builder;

/**
 * A condition that can't bes serialised.
 * This is a bit of a hack: There are a number of conditions that weren't
 * annotated for serialisation, and so serialising them would fail. This
 * just implements toProtobuf() so it throws UnsupportedOperationException
 * which has the same effect, and marks the classes I need to sort out later
 */
public abstract class InternalCondition implements Condition {
    @Override
    public Builder toProtobuf() {
        throw new UnsupportedOperationException();
    }

}
