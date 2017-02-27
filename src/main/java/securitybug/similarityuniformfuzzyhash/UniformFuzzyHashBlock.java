package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_INNER_SEPARATOR;
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
     * Rebuilds a Uniform Fuzzy Hash Block from a string representing it.
     * 
     * @param blockString String representation of a Uniform Fuzzy Hash Block.
     * @param blockStartingBytePosition Block starting byte position (0 based).
     */
    protected UniformFuzzyHashBlock(
            String blockString,
            int blockStartingBytePosition) {

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
            blockHash = Integer.parseInt(blockHashString, HEX_RADIX);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is not parseable as an hexadecimal integer.",
                    blockHashString));
        }

        if (blockHash < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is negative.",
                    blockHashString));
        }

        if (blockHash >= BLOCK_HASH_MODULO) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is greater than %s.",
                    blockHashString,
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
                    "Block size (%s) is negative.",
                    blockSizeString));
        }

        // Block positions.
        this.blockStartingBytePosition = blockStartingBytePosition;
        this.blockEndingBytePosition = blockStartingBytePosition + blockSize - 1;

    }

    /**
     * @return A string representation of this Uniform Fuzzy Hash Block.
     */
    @Override
    public String toString() {

        return Integer.toHexString(getBlockHash())
                + BLOCK_INNER_SEPARATOR
                + Integer.toHexString(getBlockSize());

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
