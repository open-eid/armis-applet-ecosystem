package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.Shareable;

public interface ShareableSignature extends Shareable {
    byte getAlgorithm();
    short getLength();
    void setInitialDigest(byte[] initialDigestBuf, short initialDigestOffset, short initialDigestLength, byte[] digestedMsgLenBuf, short digestedMsgLenOffset, short digestedMsgLenLength);
    void update(byte[] inBuff, short inOffset, short inLength);
    short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset);
    short signPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength, byte[] sigBuff, short sigOffset);
    void dispose();
}
