package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ACII_BLOCK_MAX_CHARS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_CHAR_BITS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_CHAR_ENCODER;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_ESCAPABLE_CHARS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_ESCAPE_CHAR;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_INT_CHARS_ENCODER;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_INT_CHARS_SHIFT_BITS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.ASCII_INT_MAX_CHARS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_INNER_SEPARATOR;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.HEX_BLOCK_MAX_CHARS;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.HEX_RADIX;
import static securitybug.similarityuniformfuzzyhash.UniformFuzzyHash.BLOCK_HASH_MODULO;

/**
 * This class represents a Uniform Fuzzy Hash block.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public class UniformFuzzyHashBlock {

    /**
     * Block hash.
     */
    private int blockHash;

    /**
     * Block starting byte position (0 based).
     */
    private int blockStartingBytePosition;

    /**
     * Block ending byte position (0 based).
     */
    private int blockEndingBytePosition;

    /**
     * Base constructor.
     */
    private UniformFuzzyHashBlock() {

        this.blockHash = 0;
        this.blockStartingBytePosition = 0;
        this.blockEndingBytePosition = 0;

    }

    /**
     * Constructor with arguments.
     * 
     * @param blockHash Block hash.
     * @param blockStartingBytePosition Block starting byte position (0 based).
     * @param blockEndingBytePosition Block ending byte position (0 based).
     */
    protected UniformFuzzyHashBlock(
            int blockHash,
            int blockStartingBytePosition,
            int blockEndingBytePosition) {

        this.blockHash = blockHash;
        this.blockStartingBytePosition = blockStartingBytePosition;
        this.blockEndingBytePosition = blockEndingBytePosition;

    }

    /**
     * @return A string representation of this Uniform Fuzzy Hash Block.
     *         The block is represented as two hexadecimal integers,
     *         the first one representing its hash and the second one representing its size.
     */
    @Override
    public String toString() {

        StringBuilder strB = new StringBuilder(HEX_BLOCK_MAX_CHARS);
        toString(strB);
        return strB.toString();

    }

    /**
     * Appends a string representation of this Uniform Fuzzy Hash Block to an existing
     * String Builder.
     * The block is represented as two hexadecimal integers,
     * the first one representing its hash and the second one representing its size.
     * 
     * @param strB String Builder to which the string representation of this Uniform Fuzzy Hash
     *        Block will be appended.
     */
    protected void toString(
            StringBuilder strB) {

        strB.append(Integer.toHexString(blockHash));
        strB.append(BLOCK_INNER_SEPARATOR);
        strB.append(Integer.toHexString(getBlockSize()));

    }

    /**
     * @return An ascii string representation of this Uniform Fuzzy Hash Block.
     *         The block is represented as two ascii integers,
     *         the first one representing its hash and the second one representing its size.
     */
    public String toAsciiString() {

        StringBuilder strB = new StringBuilder(ACII_BLOCK_MAX_CHARS);
        toAsciiString(strB);
        return strB.toString();

    }

    /**
     * Appends an ascii string representation of this Uniform Fuzzy Hash Block to an existing
     * String Builder.
     * The block is represented as two ascii integers,
     * the first one representing its hash and the second one representing its size.
     * 
     * @param strB String Builder to which the string representation of this Uniform Fuzzy Hash
     *        Block will be appended.
     */
    protected void toAsciiString(
            StringBuilder strB) {

        intToAscii(blockHash, strB);
        intToAscii(getBlockSize(), strB);

    }

    /**
     * Appends an ascii string representation of an integer to an existing String Builder.
     * 
     * @param integer An integer.
     * @param strB String Builder to which the string representation of the integer will be
     *        appended.
     */
    private static void intToAscii(
            int integer,
            StringBuilder strB) {

        char[] unescapedAsciiChars = new char[ASCII_INT_MAX_CHARS / 2];
        int nAsciiChars = 0;
        char asciiChar = 0;

        // Encode integer to ascii characters and put them into unescapedAsciiChars from least
        // significant to most significant.
        do {
            asciiChar = (char) (integer & ASCII_CHAR_ENCODER);
            unescapedAsciiChars[nAsciiChars++] = asciiChar;
            integer >>= ASCII_CHAR_BITS;
        } while (integer > 0);

        // Check whether the number of characters can be represented in the most significant
        // one, or an additional character is needed.
        if ((asciiChar & ASCII_INT_CHARS_ENCODER) != asciiChar) {
            nAsciiChars++;
            asciiChar = 0;
        }

        // Represent the number of characters in the last one.
        asciiChar += nAsciiChars << ASCII_INT_CHARS_SHIFT_BITS;
        unescapedAsciiChars[nAsciiChars - 1] = asciiChar;

        // Put all the characters into the string builder, from most significant to least
        // significant (the number of characters will be in the first one).
        for (int i = nAsciiChars - 1; i >= 0; i--) {
            asciiChar = unescapedAsciiChars[i];
            if (ASCII_ESCAPABLE_CHARS.contains(asciiChar)) {
                asciiChar += 2; // Escape encoding.
                strB.append(ASCII_ESCAPE_CHAR);
            }
            strB.append(asciiChar);
        }

    }

    /**
     * Rebuilds a Uniform Fuzzy Hash Block from a string representing it.
     * The block must be represented as two hexadecimal integers,
     * the first one representing its hash and the second one representing its size.
     * 
     * @param blockString String representation of a Uniform Fuzzy Hash Block.
     * @param blockStartingBytePosition Block starting byte position (0 based).
     * @return The rebuilt Uniform Fuzzy Hash Block.
     */
    protected static UniformFuzzyHashBlock rebuildFromString(
            String blockString,
            int blockStartingBytePosition) {

        // Uniform Fuzzy Hash Block.
        UniformFuzzyHashBlock block = new UniformFuzzyHashBlock();

        // Split block hash from block size.
        String[] blockSplit = blockString.split(BLOCK_INNER_SEPARATOR);

        if (blockSplit.length != 2) {
            throw new IllegalArgumentException(String.format(
                    "Block string does not fit the format blockHash%sblockSize.",
                    BLOCK_INNER_SEPARATOR));
        }

        // Block hash.
        String blockHashString = blockSplit[0].trim();

        try {
            block.blockHash = Integer.parseInt(blockHashString, HEX_RADIX);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is not parseable as an hexadecimal integer.",
                    blockHashString));
        }

        if (block.blockHash < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%d) is negative.",
                    block.blockHash));
        }

        if (block.blockHash >= BLOCK_HASH_MODULO) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%d) is greater than %s.",
                    block.blockHash,
                    Integer.toHexString(BLOCK_HASH_MODULO - 1)));
        }

        // Block size.
        String blockSizeString = blockSplit[1].trim();
        int blockSize;

        try {
            blockSize = Integer.parseInt(blockSizeString, HEX_RADIX);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Block size (%s) is not parseable as an hexadecimal integer.",
                    blockSizeString));
        }

        if (blockSize < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block size (%d) is negative.",
                    blockSize));
        }

        // Block positions.
        block.blockStartingBytePosition = blockStartingBytePosition;
        block.blockEndingBytePosition = blockStartingBytePosition + blockSize - 1;

        // Return.
        return block;

    }

    /**
     * Rebuilds a Uniform Fuzzy Hash Block from an ascii string representing it.
     * The block must be represented as two ascii integers,
     * the first one representing its hash and the second one representing its size.
     * 
     * @param blockAsciiString String containing the ascii string representation of a Uniform Fuzzy
     *        Hash Block.
     * @param offset Starting position of the ascii string representation of the Uniform Fuzzy Hash
     *        Block in blockAsciiString. It must be a 1 position int array emulating a mutable int.
     * @param blockStartingBytePosition Block starting byte position (0 based).
     * @return The rebuilt Uniform Fuzzy Hash Block.
     */
    protected static UniformFuzzyHashBlock rebuildFromAsciiString(
            String blockAsciiString,
            int[] offset,
            int blockStartingBytePosition) {

        // Uniform Fuzzy Hash Block.
        UniformFuzzyHashBlock block = new UniformFuzzyHashBlock();

        // Block hash.
        block.blockHash = asciiToInt(blockAsciiString, offset);

        if (block.blockHash < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%d) is negative.",
                    block.blockHash));
        }

        if (block.blockHash >= BLOCK_HASH_MODULO) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%d) is greater than %s.",
                    block.blockHash,
                    Integer.toHexString(BLOCK_HASH_MODULO - 1)));
        }

        // Block size.
        int blockSize = asciiToInt(blockAsciiString, offset);

        if (blockSize < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block size (%d) is negative.",
                    blockSize));
        }

        // Block positions.
        block.blockStartingBytePosition = blockStartingBytePosition;
        block.blockEndingBytePosition = blockStartingBytePosition + blockSize - 1;

        // Return.
        return block;

    }

    /**
     * Rebuilds an integer from an ascii string representing it.
     * 
     * @param asciiString String containing the ascii string representation of an integer.
     * @param offset Starting position of the ascii string representation of the integer in
     *        asciiString. It must be a 1 position int array emulating a mutable int.
     * @return The rebuilt integer.
     */
    private static int asciiToInt(
            String asciiString,
            int[] offset) {

        // Read the number of characters from the first one.
        char asciiChar = readAsciiChar(asciiString, offset);
        int nAsciiChars = asciiChar >> ASCII_INT_CHARS_SHIFT_BITS;

        // Read the integer character by character.
        // The first character is the already read character indicating the number of characters.
        int integer = asciiChar & ASCII_INT_CHARS_ENCODER;
        for (int i = 1; i < nAsciiChars; i++) {
            asciiChar = readAsciiChar(asciiString, offset);
            integer = (integer << ASCII_CHAR_BITS) + asciiChar;
        }

        return integer;

    }

    /**
     * Reads the character at an offset position from an ascii string, unescapes it in case it is
     * escaped, and checks that it is an ascii encoded character.
     * 
     * @param asciiString An ascii string.
     * @param offset An offset indicating the position of the ascii character to read from
     *        asciiString.
     * @return The read ascii character.
     */
    private static char readAsciiChar(
            String asciiString,
            int[] offset) {

        // Read the character from the string.
        char asciiChar = 0;
        try {
            asciiChar = asciiString.charAt(offset[0]++);
        } catch (StringIndexOutOfBoundsException stringIndexOutOfBoundsException) {
            throw new IllegalArgumentException(String.format(
                    "Error reading character at string position %d.",
                    offset[0] - 1));
        }

        // Check if it is an escaped character.
        if (asciiChar == ASCII_ESCAPE_CHAR) {
            try {
                asciiChar = asciiString.charAt(offset[0]++);
            } catch (StringIndexOutOfBoundsException stringIndexOutOfBoundsException) {
                throw new IllegalArgumentException(String.format(
                        "Incorrect character escape at string position %d.",
                        offset[0] - 1));
            }
            asciiChar -= 2; // Escape decoding.
        }

        // Check if it is an ascii encoded character.
        if ((asciiChar & ASCII_CHAR_ENCODER) != asciiChar) {
            throw new IllegalArgumentException(String.format(
                    "Illegal character (%s) at string position %d.",
                    asciiChar,
                    offset[0] - 1));
        }

        return asciiChar;

    }

    /**
     * Indicates whether this Uniform Fuzzy Hash Block is equal to another one.
     * 
     * @param obj Another Uniform Fuzzy Hash Block.
     * @return True if this Uniform Fuzzy Hash and the introduced one have equal hash and size.
     *         False otherwise.
     */
    @Override
    public boolean equals(
            Object obj) {

        if (obj == null) {
            return false;
        }

        if (this == obj) {
            return true;
        }

        if (obj instanceof UniformFuzzyHashBlock) {

            UniformFuzzyHashBlock other = (UniformFuzzyHashBlock) obj;

            if (this.blockHash != other.blockHash) {
                return false;
            }

            if (this.getBlockSize() != other.getBlockSize()) {
                return false;
            }

            return true;

        }

        return false;

    }

    /**
     * @return Block hash as a hashCode for this Uniform Fuzzy Hash Block.
     */
    @Override
    public int hashCode() {

        return blockHash;

    }

    /**
     * @return Block hash.
     */
    public int getBlockHash() {

        return blockHash;

    }

    /**
     * @return Block starting byte position (0 based).
     */
    public int getBlockStartingBytePosition() {

        return blockStartingBytePosition;

    }

    /**
     * @return Block ending byte position (0 based).
     */
    public int getBlockEndingBytePosition() {

        return blockEndingBytePosition;

    }

    /**
     * @return Block size in bytes.
     */
    public int getBlockSize() {

        return blockEndingBytePosition - blockStartingBytePosition + 1;

    }

}
