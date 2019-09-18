package net.lshift.spki.suiteb;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;

public interface Condition {
    public boolean allows(
            InferenceEngine engine, 
            Message action);
    SuiteBProto.Condition.Builder toProtobuf();
}
