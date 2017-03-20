package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCKS_SEPARATOR;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.FACTOR_SEPARATOR;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.getHashMaxLength;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class represents a Uniform Fuzzy Hash.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public class UniformFuzzyHash {

    /**
     * Amount of bits in a byte.
     */
    protected static final int BITS_PER_BYTE = 8;

    /**
     * Modulo of the block hashes.
     */
    protected static final int BLOCK_HASH_MODULO = Integer.MAX_VALUE;

    /**
     * Factor the hash was computed with.
     */
    private int factor;

    /**
     * Size in bytes of the data the hash was computed with.
     */
    private int dataSize;

    /**
     * Hash blocks.
     */
    private List<UniformFuzzyHashBlock> blocks;

    /**
     * Hash blocks set. Useful to compute similarities.
     */
    private Set<UniformFuzzyHashBlock> blocksSet;

    /**
     * Map from other Uniform Fuzzy Hashes to this Uniform Fuzzy Hash similarity to them.
     * Useful to cache similarities, to avoid multiple calculations of the same similarity.
     */
    private Map<UniformFuzzyHash, Double> similaritiesCache;

    /**
     * Base constructor.
     */
    private UniformFuzzyHash() {

        this.factor = 0;
        this.dataSize = 0;
        this.blocks = new LinkedList<UniformFuzzyHashBlock>();
        this.blocksSet = null;
        this.similaritiesCache = new HashMap<UniformFuzzyHash, Double>();

    }

    /**
     * Builds a Uniform Fuzzy Hash from a byte array of data and a factor.
     * 
     * @param data Byte array of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     */
    public UniformFuzzyHash(
            byte[] data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        this.factor = factor;
        this.dataSize = data.length;

        computeUniformFuzzyHash(data);
        finishBuild();

    }

    /**
     * Builds a Uniform Fuzzy Hash from a string of data (using the platform's default charset) and
     * a factor.
     * 
     * @param data String of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     */
    public UniformFuzzyHash(
            String data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        byte[] byteArray = data.getBytes();

        this.factor = factor;
        this.dataSize = byteArray.length;

        computeUniformFuzzyHash(byteArray);
        finishBuild();

    }

    /**
     * Builds a Uniform Fuzzy Hash from an input stream of data and a factor.
     * 
     * @param data Input stream of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     * @throws IOException If an IOException occurs reading the input stream of data.
     */
    public UniformFuzzyHash(
            InputStream data,
            int factor)
            throws IOException {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        byte[] byteArray = IOUtils.toByteArray(data);

        this.factor = factor;
        this.dataSize = byteArray.length;

        computeUniformFuzzyHash(byteArray);
        finishBuild();

    }

    /**
     * Builds a Uniform Fuzzy Hash from a byte array output stream of data and a factor.
     * 
     * @param data Byte array output stream of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     */
    public UniformFuzzyHash(
            ByteArrayOutputStream data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        byte[] byteArray = data.toByteArray();

        this.factor = factor;
        this.dataSize = byteArray.length;

        computeUniformFuzzyHash(byteArray);
        finishBuild();

    }

    /**
     * Builds a Uniform Fuzzy Hash from a file of data and a factor.
     * 
     * @param data File of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     * @throws IOException If an IOException occurs reading the file of data.
     */
    public UniformFuzzyHash(
            File data,
            int factor)
            throws IOException {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        if (!data.exists()) {
            throw new IllegalArgumentException("File does not exist.");
        }

        if (!data.isFile()) {
            throw new IllegalArgumentException("File is not a file.");
        }

        byte[] byteArray = IOUtils.toByteArray(new FileInputStream(data));

        this.factor = factor;
        this.dataSize = byteArray.length;

        computeUniformFuzzyHash(byteArray);
        finishBuild();

    }

    /**
     * Main algorithm computation.
     * 
     * @param data Byte array of data.
     */
    private void computeUniformFuzzyHash(
            byte[] data) {

        // Factor check.
        checkFactor(factor);

        // Size in bytes of the rolling window.
        // Size in bytes of factor + 5.
        final int windowSize = sizeInBytes(factor) + 5;

        // Window size shifter.
        // Used to extract old data from the window.
        // (2 ^ (8 * windowSize)) % factor.
        final int windowSizeShifter = shiftBytesMod(windowSize, factor);

        // Window hash match value to produce a block.
        // Any number between 0 and factor - 1 should be valid.
        final int windowHashMatchValue = factor - 1;

        // Rolling window hash.
        long windowHash = 0;

        // Block hash.
        long blockHash = 0;

        // Block starting byte position (0 based).
        int blockStartingBytePosition = 0;

        // Hash computation.
        for (int i = 0; i < data.length; i++) {

            // Unsigned datum.
            int datum = ubyte(data[i]);

            // Window hash shift, new datum addition and old datum extraction.
            if (i < windowSize) {

                windowHash = ((windowHash << BITS_PER_BYTE) + (datum)) % factor;

            } else {

                int oldDatum = ubyte(data[i - windowSize]);

                windowHash = ((windowHash << BITS_PER_BYTE) + (datum)
                        - (oldDatum * windowSizeShifter)) % factor;

                // Due to the subtraction, the modulo result might be negative.
                if (windowHash < 0) {
                    windowHash += factor;
                }

            }

            // Block hash shift and new datum addition.
            blockHash = ((blockHash << BITS_PER_BYTE) + datum) % BLOCK_HASH_MODULO;

            // Possible window hash match (block production).
            // Match is only checked if the initial window has already been computed.
            // Last data byte always produces a block.
            if ((windowHash == windowHashMatchValue && i >= windowSize - 1)
                    || (i == data.length - 1)) {

                // New block addition.
                blocks.add(new UniformFuzzyHashBlock(
                        (int) blockHash, blockStartingBytePosition, i));

                // Block hash reset.
                blockHash = 0;

                // Next block starting byte position.
                blockStartingBytePosition = i + 1;

            }

        }

    }

    /**
     * Finishes a Uniform Fuzzy Hash build.
     */
    private void finishBuild() {

        // Blocks set computation.
        blocksSet = new HashSet<UniformFuzzyHashBlock>(blocks);

        // Make blocks list and set unmodifiable.
        blocks = Collections.unmodifiableList(blocks);
        blocksSet = Collections.unmodifiableSet(blocksSet);

    }

    /**
     * Rebuilds a Uniform Fuzzy Hash from a string representing it.
     * 
     * @param hashString String representation of a Uniform Fuzzy Hash.
     */
    public UniformFuzzyHash(
            String hashString) {

        this();

        // Parameters check.
        if (hashString == null) {
            throw new NullPointerException("Hash string is null.");
        }

        // Split factor from blocks.
        String[] factorSplit = hashString.split(FACTOR_SEPARATOR.trim());

        if (factorSplit.length != 1 && factorSplit.length != 2) {
            throw new IllegalArgumentException(String.format(
                    "Hash string does not fit the format factor %s blocks.",
                    FACTOR_SEPARATOR.trim()));
        }

        // Factor.
        String factorString = factorSplit[0].trim();

        try {
            factor = Integer.parseInt(factorString);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Factor (%s) is not parseable as an integer.",
                    factorString));
        }

        checkFactor(factor);

        // Blocks.
        if (factorSplit.length == 2) {

            String blocksString = factorSplit[1].trim();
            String[] blocksSplit = blocksString.split(BLOCKS_SEPARATOR);

            int blockNumber = 0;
            int blockStartingBytePosition = 0;

            for (String blockString : blocksSplit) {

                // Block.
                blockString = blockString.trim();

                if (blockString.isEmpty()) {
                    continue;
                }

                UniformFuzzyHashBlock block = null;

                try {
                    block = new UniformFuzzyHashBlock(blockString, blockStartingBytePosition);
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new IllegalArgumentException(String.format(
                            "Block number %d (%s) could not be parsed. %s",
                            blockNumber,
                            blockString,
                            illegalArgumentException.getMessage()));
                }

                blocks.add(block);

                // Next block.
                blockNumber++;
                blockStartingBytePosition = block.getBlockEndingBytePosition() + 1;

            }

            // Data size.
            dataSize = blockStartingBytePosition;

        }

        // Finish build.
        finishBuild();

    }

    /**
     * @return A string representation of this Uniform Fuzzy Hash.
     */
    @Override
    public String toString() {

        // String builder.
        // Initial capacity enough to build the full hash string.
        StringBuilder strB = new StringBuilder(getHashMaxLength(this));

        // Factor.
        strB.append(factor);
        strB.append(FACTOR_SEPARATOR);

        // Blocks.
        for (UniformFuzzyHashBlock block : blocks) {
            strB.append(BLOCKS_SEPARATOR);
            strB.append(block);
        }

        return strB.toString();

    }

    /**
     * Computes the similarity of this Uniform Fuzzy Hash to another one and returns it as a number
     * between 0 and 1. The similarity is computed as the sum of the sizes in bytes of the blocks of
     * this Uniform Fuzzy Hash which are also in the introduced one, over the total data size in
     * bytes of this Uniform Fuzzy Hash.
     * 
     * Similarities are cached, to avoid multiple calculations of the same similarity.
     * 
     * @param other Another Uniform Fuzzy Hash.
     * @return A number between 0 and 1 representing the similarity of this Uniform Fuzzy Hash to
     *         the introduced one.
     */
    public double similarity(
            UniformFuzzyHash other) {

        // Parameters check.
        if (other == null) {
            throw new NullPointerException("The introduced Uniform Fuzzy Hash is null.");
        }

        if (other == this) {
            return 1;
        }

        if (other.factor != this.factor) {
            throw new IllegalArgumentException("The Uniform Fuzzy Hashes factors are different.");
        }

        if (this.getAmountOfBlocks() == 0 || other.getAmountOfBlocks() == 0) {
            return 0;
        }

        // Cache check.
        Double cachedSimilarity = similaritiesCache.get(other);
        if (cachedSimilarity != null) {
            return cachedSimilarity;
        }

        // Sum of the sizes in bytes of the blocks of this Uniform Fuzzy Hash which are also in the
        // introduced one.
        int sizeSum = 0;

        // Check which blocks of this Uniform Fuzzy Hash are in the set of blocks of the other
        // Uniform Fuzzy Hash.
        for (UniformFuzzyHashBlock block : this.blocks) {

            if (other.blocksSet.contains(block)) {

                // Add their size to the sum of sizes.
                sizeSum += block.getBlockSize();

            }

        }

        // Similarity computation.
        double similarity = (double) sizeSum / dataSize;

        // Cache the computed similarity.
        similaritiesCache.put(other, similarity);

        return similarity;

    }

    /**
     * Indicates whether this Uniform Fuzzy Hash is equal to another one.
     * 
     * @param obj Another Uniform Fuzzy Hash.
     * @return boolean indicating whether this Uniform Fuzzy Hash and the introduced one have equal
     *         factor, data size and blocks.
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

        if (obj instanceof UniformFuzzyHash) {

            UniformFuzzyHash other = (UniformFuzzyHash) obj;

            if (this.factor != other.factor) {
                return false;
            }

            if (this.dataSize != other.dataSize) {
                return false;
            }

            if (this.getAmountOfBlocks() != other.getAmountOfBlocks()) {
                return false;
            }

            Iterator<UniformFuzzyHashBlock> thisBlocksIterator = this.blocks.iterator();
            Iterator<UniformFuzzyHashBlock> otherBlocksIterator = other.blocks.iterator();
            while (thisBlocksIterator.hasNext()) {
                if (!thisBlocksIterator.next().equals(otherBlocksIterator.next())) {
                    return false;
                }
            }

            return true;

        }

        return false;

    }

    /**
     * A hashCode for this Uniform Fuzzy Hash based on its factor, data size and amount of blocks.
     */
    @Override
    public int hashCode() {

        final int prime = 31;
        int result = 1;

        result = prime * result + factor;
        result = prime * result + dataSize;
        result = prime * result + getAmountOfBlocks();

        return result;

    }

    /**
     * @return The factor used to compute this hash.
     */
    public int getFactor() {

        return factor;

    }

    /**
     * @return The size in bytes of the data used to compute this hash.
     */
    public int getDataSize() {

        return dataSize;

    }

    /**
     * @return The blocks of this hash.
     */
    public List<UniformFuzzyHashBlock> getBlocks() {

        return blocks;

    }

    /**
     * @return The blocks set of this hash.
     */
    public Set<UniformFuzzyHashBlock> getBlocksSet() {

        return blocksSet;

    }

    /**
     * @return The amount of blocks of this hash.
     */
    public int getAmountOfBlocks() {

        return blocks.size();

    }

    /**
     * @return The mean of this hash block size.
     */
    public double getBlockSizeMean() {

        int amountOfBlocks = getAmountOfBlocks();

        if (amountOfBlocks == 0) {
            return 0;
        }

        return (double) dataSize / amountOfBlocks;

    }

    /**
     * @return The standard deviation of this hash block size.
     */
    public double getBlockSizeStDev() {

        int amountOfBlocks = getAmountOfBlocks();

        if (amountOfBlocks <= 1) {
            return 0;
        }

        double mean = getBlockSizeMean();
        double variance = 0;

        for (UniformFuzzyHashBlock block : blocks) {
            double distanceToMean = block.getBlockSize() - mean;
            variance += distanceToMean * distanceToMean / amountOfBlocks;
        }

        return Math.sqrt(variance);

    }

    /**
     * Checks if a factor is valid to compute a Uniform Fuzzy Hash. In case it is not, an
     * IllegalArgumentException with a descriptive message is thrown.
     * 
     * @param factor Relation between data length and the hash mean number of blocks.
     */
    public static void checkFactor(
            int factor) {

        if (factor <= 2) {
            throw new IllegalArgumentException("Factor must be greater than 2.");
        }

        if (isPowerOf2(factor)) {
            throw new IllegalArgumentException("Factor must not be a power of 2.");
        }

    }

    /**
     * @param number An integer.
     * @return True if the introduced number is a power of 2. False otherwise.
     */
    private static boolean isPowerOf2(
            int number) {

        return (number > 0) && (Integer.bitCount(number) == 1);

    }

    /**
     * @param number Any integer number.
     * @return The size in bytes of the number.
     */
    private static int sizeInBytes(
            int number) {

        return ((Integer.SIZE - Integer.numberOfLeadingZeros(number) - 1) / BITS_PER_BYTE) + 1;

    }

    /**
     * @param bytesShift Amount of bytes to shift.
     * @param modulo Modulo of the operation.
     * @return (2 ^ (8 * bytesShift)) % modulo.
     */
    private static int shiftBytesMod(
            int bytesShift,
            int modulo) {

        long ret = 1;

        for (int i = 0; i < bytesShift; i++) {
            ret = (ret << BITS_PER_BYTE) % modulo;
        }

        return (int) ret;

    }

    /**
     * @param b A (signed) byte.
     * @return An integer representing the unsigned byte.
     */
    private static int ubyte(
            byte b) {

        if (b >= 0) {
            return b;
        } else {
            return (int) b - (int) 2 * Byte.MIN_VALUE;
        }

    }

}
