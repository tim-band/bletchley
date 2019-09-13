package net.lshift.spki.suiteb;

import java.io.IOException;

import org.junit.Test;

import com.google.protobuf.ByteString;
import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesCatalog;

public class PointTest extends UsesCatalog {
    @Test(expected=CryptographyException.class)
    public void badPointInPublicKeyRejected() throws IOException, InvalidInputException {
        SequenceItem.fromProtobuf(
                SuiteBProto.SequenceItem.newBuilder().setPublicSigningKey(
                SuiteBProto.PublicSigningKey.newBuilder()
                .setPoint(SuiteBProto.EcPoint.newBuilder()
                        .setX(ByteString.copyFrom("asdf".getBytes()))
                        .setY(ByteString.copyFrom("qwert".getBytes())))).build());
    }
}
