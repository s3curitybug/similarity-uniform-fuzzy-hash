package com.github.s3curitybug.similarityuniformfuzzyhash;

import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_BASE;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_INNER_SEPARATOR;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_MAX_CHARS;
import static com.github.s3curitybug.similarityuniformfuzzyhash.UniformFuzzyHash.BLOCK_HASH_MODULO;

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
     * @return The string representation of this Uniform Fuzzy Hash Block.
     */
    @Override
    public String toString() {

        StringBuilder strB = new StringBuilder(BLOCK_MAX_CHARS);
        toString(strB);
        return strB.toString();

    }

    /**
     * Appends the string representation of this Uniform Fuzzy Hash Block to an existing
     * String Builder.
     * 
     * @param strB String Builder to which the string representation of this Uniform Fuzzy Hash
     *        Block will be appended.
     */
    protected void toString(
            StringBuilder strB) {

        strB.append(Integer.toString(blockHash, BLOCK_BASE));
        strB.append(BLOCK_INNER_SEPARATOR);
        strB.append(Integer.toString(getBlockSize(), BLOCK_BASE));

    }

    /**
     * Rebuilds a Uniform Fuzzy Hash Block from its string representation.
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
        int splitIndex = blockString.lastIndexOf(BLOCK_INNER_SEPARATOR);

        if (splitIndex < 0) {
            throw new IllegalArgumentException(String.format(
                    "Block string does not fit the format blockHash%sblockSize.",
                    BLOCK_INNER_SEPARATOR));
        }

        // Block hash.
        String blockHashString = blockString.substring(0, splitIndex);

        if (blockHashString.isEmpty()) {
            throw new IllegalArgumentException(String.format(
                    "Block string does not fit the format blockHash%sblockSize.",
                    BLOCK_INNER_SEPARATOR));
        }

        try {
            block.blockHash = Integer.parseInt(blockHashString, BLOCK_BASE);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is not parseable.",
                    blockHashString));
        }

        if (block.blockHash < 0 || block.blockHash >= BLOCK_HASH_MODULO) {
            throw new IllegalArgumentException(String.format(
                    "Block hash (%s) is not parseable.",
                    blockHashString));
        }

        // Block size.
        String blockSizeString = blockString.substring(splitIndex + 1);

        if (blockSizeString.isEmpty()) {
            throw new IllegalArgumentException(String.format(
                    "Block string does not fit the format blockHash%sblockSize.",
                    BLOCK_INNER_SEPARATOR));
        }

        int blockSize;

        try {
            blockSize = Integer.parseInt(blockSizeString, BLOCK_BASE);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Block size (%s) is not parseable.",
                    blockSizeString));
        }

        if (blockSize <= 0) {
            throw new IllegalArgumentException(String.format(
                    "Block size (%s) is not parseable.",
                    blockSizeString));
        }

        // Block positions.
        block.blockStartingBytePosition = blockStartingBytePosition;
        block.blockEndingBytePosition = blockStartingBytePosition + blockSize - 1;

        // Return.
        return block;

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
