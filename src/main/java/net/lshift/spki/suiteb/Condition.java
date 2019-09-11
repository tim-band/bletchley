package net.lshift.spki.suiteb;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;

public interface Condition {
    public <ActionType extends Message> boolean allows(
            InferenceEngine<ActionType> engine, 
            ActionType action);
    SuiteBProto.Condition.Builder toProtobuf();
}
