package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * A collection of common utility methods for simplifying parsing/reading and writing TLV data on smart cards.
 */
public final class TlvUtils {

    public static final short REQUIRED_METADATA_LENGTH = (short) (TlvUtils.SIZE_OF_SHORT << 1);

    public static final byte BYTE_0 = (byte) 0;
    public static final short SHORT_0 = (short) 0;

    public static final short SIZE_OF_BYTE = (short) 1;
    public static final short SIZE_OF_SHORT = (short) 2;
    public static final byte LONGER_TLV_TAG_BITS = (byte) 0x1F; // 0b00011111

    private TlvUtils() {}

    public static byte[] getNewGlobalMetadata() {
        return (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, REQUIRED_METADATA_LENGTH);
    }

    /**
     * Returns the current parse offset stored in the metadata buffer.
     *
     * @param metadataBuffer a re-usable RAM buffer where the parsable data offset and length are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the current offset stored in the metadata buffer
     */
    public static short getParseOffset(byte[] metadataBuffer, short metadataOffset) {
        return Util.getShort(metadataBuffer, metadataOffset);
    }

    /**
     * Returns the current parse length stored in the metadata buffer.
     *
     * @param metadataBuffer a re-usable RAM buffer where the parsable data offset and length are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the current length stored in the metadata buffer
     */
    public static short getParseLength(byte[] metadataBuffer, short metadataOffset) {
        return Util.getShort(metadataBuffer, (short) (metadataOffset + SIZE_OF_SHORT));
    }

    /**
     * Initialize/update the metadata buffer (starting from the specified offset) offset value of the
     * parsable data. Offset is stored into the metadata buffer as 2-byte integer and is tightly packed.
     *
     * @param parseOffset beginning / current offset of the parsable data
     * @param metadataBuffer a re-usable RAM buffer where to write the parsable data offset and length into
     * @param metadataOffset an offset into the metadata buffer where to start writing the parsable data offset and length from
     * @return the offset right after the the metadata buffer containing also the parsable data length
     */
    public static short setParseOffset(short parseOffset, byte[] metadataBuffer, short metadataOffset) {
        // Put the offset of the parsable data into the parser metadata buffer at the request offset
        return (short) (Util.setShort(metadataBuffer, metadataOffset, parseOffset) + SIZE_OF_SHORT);
    }

    /**
     * Initialize/update the metadata buffer length value of the parsable data. Length is stored into
     * the metadata buffer as 2-byte integer and is tightly packed.
     *
     * @param parseLength (remaining) length of the parsable data
     * @param metadataBuffer a re-usable RAM buffer where to write the parsable data offset and length into
     * @param metadataOffset an offset into the metadata buffer where to start writing the parsable data offset and length from
     * @return the offset right after the the metadata buffer containing also the parsable data offset
     */
    public static short setParseLength(short parseLength, byte[] metadataBuffer, short metadataOffset) {
        // Put the length of the parsable data into the parser metadata buffer
        return Util.setShort(metadataBuffer, (short) (metadataOffset + SIZE_OF_SHORT), parseLength);
    }

    /**
     * Initialize/update the metadata buffer (starting from the specified offset) with offset and length values of the
     * parsable data. Offset and length are stored into the metadata buffer as 2-byte integers and are tightly packed.
     *
     * @param parseOffset beginning / current offset of the parsable data
     * @param parseLength (remaining) length of the parsable data
     * @param metadataBuffer a re-usable RAM buffer where to write the parsable data offset and length into
     * @param metadataOffset an offset into the metadata buffer where to start writing the parsable data offset and length from
     * @return the offset right after the final value written into the metadata buffer
     */
    public static short setParserMetadata(short parseOffset, short parseLength, byte[] metadataBuffer, short metadataOffset) {
        // Put the offset of the parsable data into the parser metadata buffer at the request offset
        metadataOffset = Util.setShort(metadataBuffer, metadataOffset, parseOffset);
        // Put the length of the parsable data into the parser metadata buffer
        return Util.setShort(metadataBuffer, metadataOffset, parseLength);
    }

    /**
     * Ensures at least {@code requiredLength} of parsable data is available (according to the metadata stored in the metadata buffer),
     * updates the offset (by incrementing it by {@code requiredLength}) and length (by decrementing it by {@code requiredLength}) values
     * stored in the metadata buffer, and returns the offset of the requested parsable data block (parsable data offset as it was before
     * incrementing it).
     *
     * @param requiredLength the requested length of the available parsable input data
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the offset of the requested parsable data block
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     *
     * @see TlvUtils#getParseOffset(byte[], short)
     * @see TlvUtils#getParseLength(byte[], short)
     */
    public static short ensureParsableInputAvailable(short requiredLength, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Extract the remaining length from the parser metadata buffer
        short available = getParseLength(parserMetadata, metadataOffset);
        // Ensure at least the requested amount of bytes are available
        if (available < requiredLength) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Extract the current offset of the parsable data
        short offset = getParseOffset(parserMetadata, metadataOffset);
        // Write the updated offset and remaining length back to parser metadata buffer
        setParserMetadata((short) (offset + requiredLength), (short) (available - requiredLength), parserMetadata, metadataOffset);
        // Return the initial extracted offset
        return offset;
    }

    /**
     * Parse a 1-byte long TLV tag from the specified source buffer at the offset stored in the metadata buffer. The parsable data offset
     * and remaining length in the metadata buffer are updated accordingly.
     *
     * @param source the source buffer where to parse the TLV tag from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the byte value of the parsed TLV tag
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     *
     * @see TlvUtils#ensureParsableInputAvailable(short, byte[], short)
     */
    public static byte parseTlvTag1(byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Ensure at least one byte is available, do all the necessary bookkeeping, and acquire the current offset of parsable data
        short offset = ensureParsableInputAvailable(SIZE_OF_BYTE, parserMetadata, metadataOffset);
        // Acquire the TLV tag from the source buffer
        byte tag1 = source[offset];
        if ((tag1 & LONGER_TLV_TAG_BITS) == LONGER_TLV_TAG_BITS) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return tag1;
    }

    /**
     * Parse a 2-bytes long TLV tag from the specified source buffer at the offset stored in the metadata buffer. The parsable data offset
     * and remaining length in the metadata buffer are updated accordingly.
     *
     * @param source the source buffer where to parse the TLV tag from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the short value of the parsed TLV tag
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     *
     * @see TlvUtils#ensureParsableInputAvailable(short, byte[], short)
     */
    public static short parseTlvTag2(byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Ensure at least two bytes are available, do all the necessary bookkeeping, and acquire the current offset of parsable data
        short offset = ensureParsableInputAvailable(SIZE_OF_SHORT, parserMetadata, metadataOffset);
        // Acquire the TLV tag bytesfrom the source buffer
        byte tag1 = source[offset];
        byte tag2 = source[++offset];
        if ((tag1 & LONGER_TLV_TAG_BITS) != LONGER_TLV_TAG_BITS || (tag2 & LONGER_TLV_TAG_BITS) == LONGER_TLV_TAG_BITS) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return Util.makeShort(tag1, tag2);
    }

    /**
     * Parse a 1 or 2-bytes long TLV tag from the specified source buffer at the offset stored in the metadata buffer. The parsable data offset
     * and remaining length in the metadata buffer are updated accordingly.
     *
     * @param source the source buffer where to parse the TLV tag from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the short value of the parsed TLV tag. If the parsed tag is just
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or parsable offset starts with 0x00 value or parsable tag is longer than 2 bytes
     *
     * @see TlvUtils#ensureParsableInputAvailable(short, byte[], short)
     */
    public static short parseTlvTag(byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Ensure at least one byte is available, do all the necessary bookkeeping, and acquire the current offset of parsable data
        short offset = ensureParsableInputAvailable(SIZE_OF_BYTE, parserMetadata, metadataOffset);
        // Acquire the TLV tag from the source buffer
        byte tag1 = BYTE_0,
             tag2 = source[offset];

        boolean isValidTag = tag2 != BYTE_0;
        if (
                isValidTag &&
                (tag2 & LONGER_TLV_TAG_BITS) == LONGER_TLV_TAG_BITS // Is longer tag
        ) {
            // Ensure also second byte is available, do all the necessary bookkeeping, and acquire the current offset of parsable data
            offset = ensureParsableInputAvailable(SIZE_OF_BYTE, parserMetadata, metadataOffset);
            // Shift the bytes and acquire the TLV tag's second byte from the source buffer
            tag1 = tag2;
            tag2 = source[offset];

            isValidTag = !((tag2 & LONGER_TLV_TAG_BITS) == LONGER_TLV_TAG_BITS) && // Is not longer tag
                         tag2 != BYTE_0;
        }
        if (!isValidTag) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return Util.makeShort(tag1, tag2);
    }

    /**
     * Parse a 1-byte long TLV tag from the specified source buffer at the offset stored in the metadata buffer and ensure it matches the expected tag.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * @param expectedTag the expected TLV tag
     * @param source the source buffer where to parse the TLV tag from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the offset of the requested parsable data block
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the TLV tag parsed from the source buffer does not match the one that was expected
     *
     * @see TlvUtils#parseTlvTag1(byte[], byte[], short)
     */
    public static short ensureTlvTag1(byte expectedTag, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        short offset = getParseOffset(parserMetadata, metadataOffset);
        // Parse the actual TLV tag from the source buffer
        byte actualTag = parseTlvTag1(source, parserMetadata, metadataOffset);
        // Ensure the TLV tag is what was expected
        if (expectedTag != actualTag) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return offset;
    }

    /**
     * Parse a 2-bytes long TLV tag from the specified source buffer at the offset stored in the metadata buffer and ensure it matches the expected tag.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * @param expectedTag the expected TLV tag
     * @param source the source buffer where to parse the TLV tag from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the offset of the requested parsable data block
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the TLV tag parsed from the source buffer does not match the one that was expected
     *
     * @see TlvUtils#parseTlvTag2(byte[], byte[], short)
     */
    public static short ensureTlvTag2(short expectedTag, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        short offset = getParseOffset(parserMetadata, metadataOffset);
        // Parse the actual TLV tag from the source buffer
        short actualTag = parseTlvTag2(source, parserMetadata, metadataOffset);
        // Ensure the TLV tag is what was expected
        if (expectedTag != actualTag) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return offset;
    }

    /**
     * Parse the TLV length from the specified source buffer at the offset stored in the metadata buffer.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * Can also be used without metadata buffer. Having metadata buffer absent
     *
     * NB: Supports only definite lengths encoded using 1, 2 or 3 bytes that fit into a signed 16-bit integer!
     *
     * @param source the source buffer where to parse the TLV length from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the parsed TLV length
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the length is indefinite or the length is larger than fits into a signed 16-bit integer
     *
     * @see TlvUtils#ensureParsableInputAvailable(short, byte[], short)
     */
    public static short parseTlvLength(byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Ensure at least one byte is available, do all the necessary bookkeeping, and acquire the current offset of parsable data
        short offset = ensureParsableInputAvailable(SIZE_OF_BYTE, parserMetadata, metadataOffset);

        // Acquire the length byte value from buffer
        short length = (short) (source[offset] & 0xFF);
        // If length encoded as a single byte: done, return the length
        if ((byte) (length & 0x80) == BYTE_0) {
            return length;
        }

        // Acquire the number of following octets
        length = (short) (length & 0x7F);
        // Indefinite length not supported, longer than 2-byte length not supported
        if (length < SIZE_OF_BYTE || length > SIZE_OF_SHORT) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Ensure at least the required number of bytes is available, do all the necessary bookkeeping, and acquire the current offset of parsable data
        offset = ensureParsableInputAvailable(length, parserMetadata, metadataOffset);

        // If 1 following octet: extract and return the length
        if (length == SIZE_OF_BYTE) {
            return (short) (source[offset] & 0xFF);
        }

        // 2 following octets: acquire the 16-bit length
        length = Util.getShort(source, offset);
        // Length was probably too large
        if (length < SHORT_0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Return the length
        return length;
    }

    /**
     * Parse the TLV length from the specified source buffer at the offset stored in the metadata buffer and ensure it matches the expected length.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * NB: Supports only definite lengths encoded using 1, 2 or 3 bytes that fit into a signed 16-bit integer!
     *
     * @param expectedLength the expected TLV length
     * @param source the source buffer where to parse the TLV length from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the length is indefinite or the length is larger than fits into a signed 16-bit integer or the or the TLV tag parsed
     * from the source buffer does not match the one that was expected
     *
     * @see TlvUtils#parseTlvLength(byte[], byte[], short)
     */
    public static void ensureTlvLength(short expectedLength, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Parse the actual TLV length from the source buffer
        short actualLength = parseTlvLength(source, parserMetadata, metadataOffset);
        // Ensure the TLV length is what was expected
        if (expectedLength != actualLength) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * Parse a 1-byte long TLV tag from the specified source buffer at the offset stored in the metadata buffer and ensure it matches the expected tag,
     * then parse and return the TLV length.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * NB: Supports only definite lengths encoded using 1, 2 or 3 bytes that fit into a signed 16-bit integer!
     *
     * @param expectedTag the expected TLV tag
     * @param source the source buffer where to parse the TLV tag and length from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the parsed TLV length
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the TLV tag parsed from the source buffer does not match the one that was expected or the TLV length is indefinite
     * or the length is larger than fits into a signed 16-bit integer
     *
     * @see TlvUtils#ensureTlvTag1(byte, byte[], byte[], short)
     * @see TlvUtils#parseTlvLength(byte[], byte[], short)
     */
    public static short ensureTlvTag1AndParseLength(byte expectedTag, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Parse the TLV tag and ensure it is what was expected
        ensureTlvTag1(expectedTag, source, parserMetadata, metadataOffset);
        // Parse and return the actual TLV length
        return parseTlvLength(source, parserMetadata, metadataOffset);
    }

    /**
     * Parse a 2-bytes long TLV tag from the specified source buffer at the offset stored in the metadata buffer and ensure it matches the expected tag,
     * then parse and return the TLV length.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * NB: Supports only definite lengths encoded using 1, 2 or 3 bytes that fit into a signed 16-bit integer!
     *
     * @param expectedTag the expected TLV tag
     * @param source the source buffer where to parse the TLV tag and length from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the parsed TLV length
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code requiredLength} exceeds the remaining length of parsable data
     * or the TLV tag parsed from the source buffer does not match the one that was expected or the TLV length is indefinite
     * or the length is larger than fits into a signed 16-bit integer
     *
     * @see TlvUtils#ensureTlvTag2(short, byte[], byte[], short)
     * @see TlvUtils#parseTlvLength(byte[], byte[], short)
     */
    public static short ensureTlvTag2AndParseLength(short expectedTag, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Parse the TLV tag and ensure it is what was expected
        ensureTlvTag2(expectedTag, source, parserMetadata, metadataOffset);
        // Parse and return the actual TLV length
        return parseTlvLength(source, parserMetadata, metadataOffset);
    }

    /**
     * Parse and return an integer value of the specified length from the specified source buffer at the offset stored in the metadata buffer.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * NB: Supports only integer values that fit into a signed 16-bit integer!
     *
     * @param length the length (in bytes) of the integer to parse
     * @param source the source buffer where to parse the integer from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the parsed integer value
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case {@code length} exceeds the remaining length of parsable data
     * or {@code length} is less than 1 or greater than 2
     *
     * @see TlvUtils#ensureParsableInputAvailable(short, byte[], short)
     */
    public static short parseTlvInteger(short length, byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        switch (length) {
            case SIZE_OF_BYTE:
                // Ensure at least one byte is available, do all the necessary bookkeeping, and parse and return the value from the acquired offset
                return source[ensureParsableInputAvailable(SIZE_OF_BYTE, parserMetadata, metadataOffset)];
            case SIZE_OF_SHORT:
                // Ensure at least two bytes are available, do all the necessary bookkeeping, and parse and return the value from the acquired offset
                return Util.getShort(source, ensureParsableInputAvailable(SIZE_OF_SHORT, parserMetadata, metadataOffset));
            default:
                // Larger than 16-bit integers are not representable in the code, 0 and negative lengths are not valid
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                return SHORT_0; // For compiler
        }
    }

    /**
     * Parse the TLV length from the specified source buffer at the offset stored in the metadata buffer, then
     * parse and return an integer value of the acquired length from the specified source buffer at the offset stored in the metadata buffer.
     * The parsable data offset and remaining length in the metadata buffer are updated accordingly.
     *
     * NB: Supports only integer values that fit into a signed 16-bit integer!
     *
     * @param source the source buffer where to parse the integer from
     * @param parserMetadata a re-usable RAM buffer where the current offset and length of the parsable data are stored in
     * @param metadataOffset an offset into the metadata buffer where the current offset and length of the parsable data are stored in
     * @return the parsed integer value
     *
     * @throws ISOException {@link ISO7816#SW_DATA_INVALID} in case the TLV length + integer exceeds the remaining length of parsable data
     * or the TLV length is indefinite or the TLV length is larger than fits into a signed 16-bit integer
     * or length of the integer value is less than 1 or greater than 2
     *
     * @see TlvUtils#parseTlvLength(byte[], byte[], short)
     * @see TlvUtils#parseTlvInteger(short, byte[], byte[], short)
     */
    public static short parseTlvInteger(byte[] source, byte[] parserMetadata, short metadataOffset) throws ISOException {
        // Parse and acquire the length of the subsequent integer value
        short length = parseTlvLength(source, parserMetadata, metadataOffset);
        // Parse and return the integer value of the previously acquired length
        return parseTlvInteger(length, source, parserMetadata, metadataOffset);
    }

    /**
     * Write a 1-byte long TLV tag followed by TLV length into the specified destination buffer starting from the specified offset
     * and return the offset right after the final byte written into the buffer.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param tag the byte value of the TLV tag to write
     * @param length the TLV length to write
     * @param buffer the destination buffer to write the TLV tag and length into
     * @param offset the offset into the destination buffer where to start writing the TLV tag and length from
     * @return the offset right after the final byte written into the destination buffer
     *
     * @see TlvUtils#writeTlvLength(short, byte[], short)
     */
    public static short writeTlvTag1AndLength(byte tag, short length, byte[] buffer, short offset) {
        // Write the TLV tag and increment the offset
        buffer[offset++] = tag;
        // Write the TLV length and return the new offset
        return writeTlvLength(length, buffer, offset);
    }

    /**
     * Write a 2-bytes long TLV tag followed by TLV length into the specified destination buffer starting from the specified offset
     * and return the offset right after the final byte written into the buffer.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param tag the short value of the TLV tag to write
     * @param length the TLV length to write
     * @param buffer the destination buffer to write the TLV tag and length into
     * @param offset the offset into the destination buffer where to start writing the TLV tag and length from
     * @return the offset right after the final byte written into the destination buffer
     *
     * @see TlvUtils#writeTlvLength(short, byte[], short)
     */
    public static short writeTlvTag2AndLength(short tag, short length, byte[] buffer, short offset) {
        // Write the TLV tag and increment the offset
        offset = Util.setShort(buffer, offset, tag);
        // Write the TLV length and return the new offset
        return writeTlvLength(length, buffer, offset);
    }

    /**
     * Write a TLV length into the specified destination buffer starting from the specified offset
     * and return the offset right after the final byte written into the buffer.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the TLV length to write
     * @param buffer the destination buffer to write the TLV tag and length into
     * @param offset the offset into the destination buffer where to start writing the TLV tag and length from
     * @return the offset right after the final byte written into the destination buffer
     */
    public static short writeTlvLength(short length, byte[] buffer, short offset) {
        if (length < (short) 0x80) {
            // Write the short form of the length and increment the offset
            buffer[offset++] = (byte) (length & 0x7F);
        } else if (length < (short) 0x100) {
            // Write the first octet of the long form length and increment the offset
            buffer[offset++] = (byte) (0x80 | SIZE_OF_BYTE);
            // Write the following octet of the long form length and increment the offset
            buffer[offset++] = (byte) (length & 0xFF);
        } else {
            // Write the first octet of the long form length and increment the offset
            buffer[offset++] = (byte) (0x80 | SIZE_OF_SHORT);
            // Write the following octets of the long form length and acquire the new offset
            offset = Util.setShort(buffer, offset, length);
        }
        // Return the new offset
        return offset;
    }

    /**
     * Calculate the number of bytes required for 1-byte long TLV tag + TLV length + TLV value of the specified length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the length of the TLV value
     * @return the number of required bytes
     *
     * @see TlvUtils#bytesRequiredForTlvLength(short)
     */
    public static short bytesRequiredForTlv1(short length) {
        return (short) (SIZE_OF_BYTE + bytesRequiredForTlvLength(length) + length);
    }

    /**
     * Calculate the number of bytes required for 2-bytes long TLV tag + TLV length + TLV value of the specified length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the length of the TLV value
     * @return the number of required bytes
     *
     * @see TlvUtils#bytesRequiredForTlvLength(short)
     */
    public static short bytesRequiredForTlv2(short length) {
        return (short) (SIZE_OF_SHORT + bytesRequiredForTlvLength(length) + length);
    }

    /**
     * Calculate the number of bytes required for 1-byte long TLV tag + the specified TLV length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the length of the TLV value
     * @return the number of required bytes
     *
     * @see TlvUtils#bytesRequiredForTlvLength(short)
     */
    public static short bytesRequiredForTlvTag1AndLength(short length) {
        return (short) (SIZE_OF_BYTE + bytesRequiredForTlvLength(length));
    }

    /**
     * Calculate the number of bytes required for 2-byte long TLV tag + the specified TLV length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the length of the TLV value
     * @return the number of required bytes
     *
     * @see TlvUtils#bytesRequiredForTlvLength(short)
     */
    public static short bytesRequiredForTlvTag2AndLength(short length) {
        return (short) (SIZE_OF_SHORT + bytesRequiredForTlvLength(length));
    }

    /**
     * Calculate the number of bytes required for TLV length + TLV value of the specified length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the length of the TLV value
     * @return the number of required bytes
     *
     * @see TlvUtils#bytesRequiredForTlvLength(short)
     */
    public static short bytesRequiredForTlvLengthAndValue(short length) {
        return (short) (bytesRequiredForTlvLength(length) + length);
    }

    /**
     * Calculate the number of bytes required for the specified TLV length.
     *
     * NB: length must be a valid non-negative 16-bit integer!
     *
     * @param length the TLV length
     * @return the number of bytes required
     */
    public static short bytesRequiredForTlvLength(short length) {
        if (length < (short) 0x80) {
            return SIZE_OF_BYTE;
        } else if (length < (short) 0x100) {
            return (short) (SIZE_OF_BYTE + SIZE_OF_BYTE);
        } else {
            return (short) (SIZE_OF_BYTE + SIZE_OF_SHORT);
        }
    }

}
