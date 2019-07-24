package net.lshift.spki.suiteb.proto;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.math.ec.ECPoint;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.CryptographyException;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.DigestSha384.Step;
import net.lshift.spki.suiteb.InvalidOnOrAfter;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.UntrustedCondition;
import net.lshift.spki.suiteb.ValidOnOrAfter;
import net.lshift.spki.suiteb.sexpstructs.ECPointConverter;
import net.lshift.spki.suiteb.sexpstructs.ECPointConverter.Point;
import net.lshift.spki.suiteb.sexpstructs.Hash;


public class ProtobufHelper {
    public static final net.lshift.spki.suiteb.PublicEncryptionKey.Step publicEncryptionKeyConverter = new PublicEncryptionKey.Step();
    private static final ECPointConverter ecPointConverter = new ECPointConverter();
    private static final Step digestSha384Converter = new DigestSha384.Step();

    private ProtobufHelper() {
        // It might be necessary for this to have a catalog of condition converters
        // in the short term, in which case none of this would be static.
        // It is also possible to add a catalog for action converters, but I think
        // we should just expose that actions are Any.
    }
    
    public static Condition fromProtobuf(SuiteBProto.Condition pb) throws InvalidInputException {
        switch(pb.getConditionCase()) {
        case UNTRUSTED:
            return UntrustedCondition.UNTRUSTED;
        case VALID_ON_OR_AFTER:
            return new ValidOnOrAfter(toDate(pb.getValidOnOrAfter().getDate()));
        case INVALID_ON_OR_AFTER:
            return new InvalidOnOrAfter(toDate(pb.getInvalidOnOrAfter().getDate()));
        case EXTENSION:
        case CONDITION_NOT_SET:
        default:
            throw new InvalidInputException("Invalid condition");
        }
    }
    
    public static ECPoint ecPointFromProtobuf(SuiteBProto.EcPoint pb) throws CryptographyException {
        return ecPointConverter.stepOut(
                new Point(toBigInteger(pb.getX()), toBigInteger(pb.getY())));
    }
    
    public static BigInteger toBigInteger(ByteString s) {
        return new BigInteger(s.toByteArray());
    }
    
    public static DigestSha384 toDigest(net.lshift.bletchley.suiteb.proto.SuiteBProto.Hash hash) 
            throws InvalidInputException {
        return digestSha384Converter.stepOut(new Hash(
                hash.getType(), 
                hash.getValue().toByteArray()));
    }
    
    private static Date toDate(Timestamp timestamp) {
        return new Date(Timestamps.toMillis(timestamp));
    }
    
    public static final Timestamp fromDate(Date date) {
        return Timestamps.fromMillis(date.getTime());
    }

    public static ByteString toProtobuf(BigInteger i) {
        return ByteString.copyFrom(i.toByteArray());
    }

    public static SuiteBProto.EcPoint.Builder toProtobuf(ECPoint point) {
        return toProtobuf(ecPointConverter.stepIn(point));
    }

    private static SuiteBProto.EcPoint.Builder toProtobuf(Point ecPoint) {
        return SuiteBProto.EcPoint.newBuilder()
                .setX(toProtobuf(ecPoint.x))
                .setY(toProtobuf(ecPoint.y));
    }
}
