package net.lshift.spki.suiteb;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.convert.Convert;

@Convert.Discriminated({
    UntrustedCondition.class,
    InvalidOnOrAfter.class,
    ValidOnOrAfter.class
})
public interface Condition {
    boolean allows(InferenceEngine engine, ActionType action);
    SuiteBProto.Condition.Builder toProtobuf();
}
