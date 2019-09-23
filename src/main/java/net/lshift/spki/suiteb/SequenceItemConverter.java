package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.SequenceUtils.action;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.DiscardUnknownFieldsParser;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.Parser;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.passphrase.PassphraseProtectedKey;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

public class SequenceItemConverter {

    private static final Parser<SuiteBProto.SequenceItem> protobufParser = 
            DiscardUnknownFieldsParser.wrap(SuiteBProto.SequenceItem.parser());
    public final Map<String, Message> actionDefaultInstanceByName;
    
    @SafeVarargs
    public SequenceItemConverter(Class<? extends Message> ... actionTypes) {
        Map<String, Message> byName = new HashMap<>();
        for(Class<? extends Message> actionType: actionTypes) {
            Message defaultInstance = getDefaultInstance(actionType);
            byName.put(defaultInstance.getDescriptorForType().getFullName(), defaultInstance);
        }

        this.actionDefaultInstanceByName = Collections.unmodifiableMap(byName);
    }

    /**
     * Get the default instance for the message type.
     * The default instance allows access to a range of meta-data.
     * There is an internal implementation of this, but the author says
     * we shouldn't use it. This is simple, and based on the static
     * method getDefaultInstance existing in type, which is part of the
     * converter specification.
     * @param type
     * @return
     */
    public static Message getDefaultInstance(Class<? extends Message> type) {
       try {
           Method method = type.getMethod("getDefaultInstance");
           return (Message) method.invoke(method);
         } catch (Exception e) {
           throw new IllegalArgumentException(
               "Failed to get default instance for " + type, e);
         }
    }
    
    public SequenceItem parse(byte [] bytes) throws InvalidInputException {
        try {
            return fromProtobuf(protobufParser.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e); 
        }
    }    

    public SequenceItem parse(ByteString bytes) throws InvalidInputException {
        try {
            return fromProtobuf(protobufParser.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e); 
        }
    }    

    public SequenceItem parse(Openable input) 
            throws InvalidInputException, IOException {
        try(InputStream is = input.read()) {
            return parse(is);
        }
    }

    public SequenceItem parse(InputStream is) throws InvalidInputException {
        try {
            return fromProtobuf(protobufParser.parseFrom(is));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e);
        }
    }

    /**
     * Convert from the protocol buffer representation to the
     * internal representation.
     * @param pb the protocol buffer representation
     * @return the internal representation.
     * @throws InvalidInputException
     */
    public SequenceItem fromProtobuf(SuiteBProto.SequenceItem pb) throws InvalidInputException {
        switch(pb.getItemCase()) {
        case ACTION:
            return fromProtobuf(pb.getAction());
        case AES_KEY:
            return new AesKey(pb.getAesKey().getKey().toByteArray());
        case AES_PACKET:
            return new AesPacket(
                    AesKeyId.fromProtobuf(pb.getAesPacket().getKeyId()), 
                    pb.getAesPacket().getNonce().toByteArray(),
                    pb.getAesPacket().getCiphertext().toByteArray());
        case HASH:
            return ProtobufHelper.toDigest(pb.getHash());
        case ECDH_ITEM:
            return EcdhItem.fromProtobuf(pb.getEcdhItem());
        case LIMIT:
            return fromProtobuf(pb.getLimit());
        case PRIVATE_ENCRYPTION_KEY:
            return PrivateEncryptionKey.fromProtobuf(pb.getPrivateEncryptionKey());
        case PUBLIC_ENCRYPTION_KEY:
            return PublicEncryptionKey.fromProtobuf(pb.getPublicEncryptionKey());
        case PUBLIC_SIGNING_KEY:
            return PublicSigningKey.fromProtobuf(pb.getPublicSigningKey());
        case SEQUENCE:
            return fromProtobuf(pb.getSequence());
        case SIGNATURE:
            return Signature.fromProtobuf(pb.getSignature());
        case SIGNED:
            return fromProtobuf(pb.getSigned());
        case PASSPHRASE_PROTECTED_KEY:
            return PassphraseProtectedKey.fromProtobuf(pb.getPassphraseProtectedKey());
        case ITEM_NOT_SET:
            throw new InvalidInputException("Empty sequence item");
        default:
            throw new InvalidInputException("Unknown sequence item type");
        }
    }

    public Action fromProtobuf(SuiteBProto.Action action) throws InvalidInputException {
        try {
            String typeName = Action.typeName(action.getAccept().getTypeUrl());
            Message actionDefaultInstance = actionDefaultInstanceByName.get(typeName);
            if(actionDefaultInstance == null) {
                throw new InvalidInputException(MessageFormat.format(
                        "Action name {0} not one of {1}.", 
                        typeName,
                        actionDefaultInstanceByName.keySet())); 
            }
            return action(
                    DiscardUnknownFieldsParser.wrap(
                            actionDefaultInstance.getParserForType()).parseFrom(action.getAccept().getValue()));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidInputException(e);
        }
    }
    
    public Sequence fromProtobuf(SuiteBProto.Sequence sequence) throws InvalidInputException {
        // Because of exception handling, this doesn't use Stream#map
        List<SequenceItem> items = new ArrayList<>(sequence.getItemsCount());
        for(SuiteBProto.SequenceItem item: sequence.getItemsList()) {
            items.add(fromProtobuf(item));
        }
        return new Sequence(items);
    }

    public Signed fromProtobuf(SuiteBProto.Signed signed) throws InvalidInputException {
        return new Signed(signed.getHashType(), fromProtobuf(signed.getPayload()));
    }

    public SequenceItem fromProtobuf(SuiteBProto.Limit limit) throws InvalidInputException {
        List<Condition> conditions = new ArrayList<>(limit.getConditionCount());
        for(SuiteBProto.Condition condition: limit.getConditionList()) {
            conditions.add(ProtobufHelper.fromProtobuf(condition));
        }
        return new Limit(fromProtobuf(limit.getSubject()), conditions);
    }

    public List<Descriptor> getDescriptors() {
        return actionDefaultInstanceByName.values().stream().map(Message::getDescriptorForType).collect(Collectors.toList());
    }
}
