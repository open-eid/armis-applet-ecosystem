package ee.openeid.armis.applet.ecosystem;

import ee.openeid.armis.applet.ecosystem.libs.ShareableSignature;
import javacard.framework.JCSystem;
import javacard.security.Signature;

public class SharedSignature implements ShareableSignature {

    private Signature signature;

    SharedSignature(Signature signature) {
        this.signature = signature;
    }

    @Override
    public byte getAlgorithm() {
        return signature.getAlgorithm();
    }

    @Override
    public short getLength() {
        return signature.getLength();
    }

    @Override
    public void setInitialDigest(byte[] initialDigestBuf, short initialDigestOffset, short initialDigestLength, byte[] digestedMsgLenBuf, short digestedMsgLenOffset, short digestedMsgLenLength) {
        signature.setInitialDigest(initialDigestBuf, initialDigestOffset, initialDigestLength, digestedMsgLenBuf, digestedMsgLenOffset, digestedMsgLenLength);
    }

    @Override
    public void update(byte[] inBuff, short inOffset, short inLength) {
        signature.update(inBuff, inOffset, inLength);
    }

    @Override
    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) {
        return signature.sign(inBuff, inOffset, inLength, sigBuff, sigOffset);
    }

    @Override
    public short signPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength, byte[] sigBuff, short sigOffset) {
        return signature.signPreComputedHash(hashBuff, hashOffset, hashLength, sigBuff, sigOffset);
    }

    @Override
    public void dispose() {
        signature = null;
        JCSystem.requestObjectDeletion();
    }

}
