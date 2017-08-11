package com.github.s3curitybug.similarityuniformfuzzyhash;

import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCKS_SEPARATOR;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.BLOCK_WITH_SEP_MAX_CHARS;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.FACTOR_SEPARATOR;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.FACTOR_WITH_SEP_MAX_CHARS;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
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
     * Modulo of the block hashes.
     */
    protected static final int BLOCK_HASH_MODULO = Integer.MAX_VALUE;

    /**
     * Enum of types of similarity.
     */
    public enum SimilarityTypes {

        /**
         * Similarity of a hash to other hashes.
         */
        SIMILARITY("Similarity"),

        /**
         * Similarity of other hashes to a hash.
         */
        REVERSE_SIMILARITY("Reverse"),

        /**
         * Maximum similarity between Similarity and Reverse.
         */
        MAXIMUM("Maximum"),

        /**
         * Minimum similarity between Similarity and Reverse.
         */
        MINIMUM("Minimum"),

        /**
         * Arithmetic mean between Similarity and Reverse, (Similarity * Reverse) / 2.
         */
        ARITHMETIC_MEAN("ArithMean"),

        /**
         * Geometric mean between Similarity and Reverse, sqrt(Similarity * Reverse).
         */
        GEOMETRIC_MEAN("GeomMean");

        /**
         * Similarity type name.
         */
        private String name;

        /**
         * Constructor.
         * 
         * @param name Similarity type name.
         */
        SimilarityTypes(
                String name) {

            this.name = name;

        }

        /**
         * @return The similarity type name.
         */
        public String getName() {

            return name;

        }

        /**
         * @return A list with all the similarity types names.
         */
        public static List<String> names() {

            SimilarityTypes[] similarityTypes = SimilarityTypes.values();
            List<String> similarityTypesNames = new ArrayList<>(similarityTypes.length);

            for (SimilarityTypes similarityType : similarityTypes) {
                similarityTypesNames.add(similarityType.name);
            }

            return similarityTypesNames;

        }

    }

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
     * Base constructor.
     */
    private UniformFuzzyHash() {

        this.factor = 0;
        this.dataSize = 0;
        this.blocks = null;
        this.blocksSet = null;

    }

    /**
     * Builds a Uniform Fuzzy Hash from a byte array of data and a factor.
     * 
     * @param data Byte array of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
     */
    public UniformFuzzyHash(
            byte[] data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        computeUniformFuzzyHash(data, factor);

    }

    /**
     * Builds a Uniform Fuzzy Hash from a string of data (using the platform's default charset) and
     * a factor.
     * 
     * @param data String of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
     */
    public UniformFuzzyHash(
            String data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        byte[] byteArray = data.getBytes();
        computeUniformFuzzyHash(byteArray, factor);

    }

    /**
     * Builds a Uniform Fuzzy Hash from an input stream of data and a factor.
     * 
     * @param data Input stream of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
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
        computeUniformFuzzyHash(byteArray, factor);

    }

    /**
     * Builds a Uniform Fuzzy Hash from a byte array output stream of data and a factor.
     * 
     * @param data Byte array output stream of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
     */
    public UniformFuzzyHash(
            ByteArrayOutputStream data,
            int factor) {

        this();

        if (data == null) {
            throw new NullPointerException("Data is null.");
        }

        byte[] byteArray = data.toByteArray();
        computeUniformFuzzyHash(byteArray, factor);

    }

    /**
     * Builds a Uniform Fuzzy Hash from a file of data and a factor.
     * 
     * @param data File of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
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
            throw new IllegalArgumentException(String.format(
                    "File %s does not exist.",
                    data.getName()));
        }

        if (!data.isFile()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a file.",
                    data.getName()));
        }

        byte[] byteArray = null;
        try (InputStream inputStream = new FileInputStream(data)) {
            byteArray = IOUtils.toByteArray(inputStream);
        }
        computeUniformFuzzyHash(byteArray, factor);

    }

    /**
     * Main algorithm computation.
     * 
     * @param data Byte array of data.
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
     */
    private void computeUniformFuzzyHash(
            byte[] data,
            int factor) {

        // Factor check.
        checkFactor(factor);

        // Attributes assignment.
        this.factor = factor;
        this.dataSize = data.length;
        this.blocks = new LinkedList<>();

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

                windowHash = ((windowHash << Byte.SIZE) + (datum)) % factor;

            } else {

                int oldDatum = ubyte(data[i - windowSize]);

                windowHash = ((windowHash << Byte.SIZE) + (datum)
                        - (oldDatum * windowSizeShifter)) % factor;

                // Due to the subtraction, the modulo result might be negative.
                if (windowHash < 0) {
                    windowHash += factor;
                }

            }

            // Block hash shift and new datum addition.
            blockHash = ((blockHash << Byte.SIZE) + datum) % BLOCK_HASH_MODULO;

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
     * @return The string representation of this Uniform Fuzzy Hash.
     */
    @Override
    public String toString() {

        // String builder.
        // Initial capacity enough to build the full hash string.
        StringBuilder strB = new StringBuilder(
                FACTOR_WITH_SEP_MAX_CHARS + BLOCK_WITH_SEP_MAX_CHARS * blocks.size());

        // Factor.
        strB.append(factor);
        strB.append(FACTOR_SEPARATOR);

        // Blocks.
        int i = 0;
        for (UniformFuzzyHashBlock block : blocks) {
            if (i++ != 0) {
                strB.append(BLOCKS_SEPARATOR);
            }
            block.toString(strB);
        }

        return strB.toString();

    }

    /**
     * Rebuilds a Uniform Fuzzy Hash from its string representation.
     * 
     * @param hashString String representation of a Uniform Fuzzy Hash.
     * @return The rebuilt Uniform Fuzzy Hash.
     */
    public static UniformFuzzyHash rebuildFromString(
            String hashString) {

        // Parameters check.
        if (hashString == null) {
            throw new NullPointerException("Hash string is null.");
        }

        // Uniform Fuzzy Hash.
        UniformFuzzyHash hash = new UniformFuzzyHash();

        // Split factor from blocks.
        int splitIndex = hashString.indexOf(FACTOR_SEPARATOR);

        if (splitIndex < 0) {
            throw new IllegalArgumentException(String.format(
                    "Hash string does not fit the format factor%sblocks.",
                    FACTOR_SEPARATOR));
        }

        // Factor.
        String factorString = hashString.substring(0, splitIndex);

        if (factorString.isEmpty()) {
            throw new IllegalArgumentException(String.format(
                    "Hash string does not fit the format factor%sblocks.",
                    FACTOR_SEPARATOR));
        }

        try {
            hash.factor = Integer.parseInt(factorString);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException(String.format(
                    "Factor (%s) is not parseable.",
                    factorString.isEmpty()));
        }

        checkFactor(hash.factor);

        // Blocks.
        String blocksString = hashString.substring(splitIndex + 1);

        hash.blocks = new LinkedList<>();

        int blockNumber = 0;
        int blockStartingBytePosition = 0;

        if (!blocksString.isEmpty()) {

            splitIndex = 0;
            int lastSplitIndex = 0;
            while (splitIndex >= 0) {

                splitIndex = blocksString.indexOf(BLOCKS_SEPARATOR, lastSplitIndex);
                String blockString = null;
                if (splitIndex >= 0) {
                    blockString = blocksString.substring(lastSplitIndex, splitIndex);
                } else {
                    blockString = blocksString.substring(lastSplitIndex);
                }
                lastSplitIndex = splitIndex + BLOCKS_SEPARATOR.length();

                // Block.
                UniformFuzzyHashBlock block = null;

                try {
                    block = UniformFuzzyHashBlock.rebuildFromString(
                            blockString, blockStartingBytePosition);
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new IllegalArgumentException(String.format(
                            "Block number %d (%s) could not be parsed. %s",
                            blockNumber,
                            blockString.isEmpty() ? "<empty>" : blockString,
                            illegalArgumentException.getMessage()));
                }

                hash.blocks.add(block);

                // Next block.
                blockNumber++;
                blockStartingBytePosition = block.getBlockEndingBytePosition() + 1;

            }

        }

        // Data size.
        hash.dataSize = blockStartingBytePosition;

        // Return.
        return hash;

    }

    /**
     * Computes the similarity of this Uniform Fuzzy Hash to another one and returns it as a number
     * between 0 and 1.
     * The similarity is computed as the sum of the sizes in bytes of the blocks of this Uniform
     * Fuzzy Hash which are also in the introduced one, over the total data size in bytes of this
     * Uniform Fuzzy Hash.
     * 
     * @param other Another Uniform Fuzzy Hash.
     * @return A number between 0 and 1 representing the similarity of this Uniform Fuzzy Hash to
     *         the introduced one.
     */
    public double similarity(
            UniformFuzzyHash other) {

        // Parameters check.
        if (other == null) {
            throw new NullPointerException("The Uniform Fuzzy Hash is null.");
        }

        if (other == this) {
            return 1;
        }

        if (other.factor != this.factor) {
            throw new IllegalArgumentException("The Uniform Fuzzy Hashes factors are different.");
        }

        if (this.blocks.size() == 0 || other.blocks.size() == 0) {
            return 0;
        }

        // Sum of the sizes in bytes of the blocks of this Uniform Fuzzy Hash which are also in the
        // introduced one.
        int sizeSum = 0;

        // Check which blocks of this Uniform Fuzzy Hash are in the set of blocks of the other
        // Uniform Fuzzy Hash.
        other.accessBlocksSet();

        for (UniformFuzzyHashBlock block : this.blocks) {

            if (other.blocksSet.contains(block)) {

                // Add their size to the sum of sizes.
                sizeSum += block.getBlockSize();

            }

        }

        // Similarity computation.
        double similarity = (double) sizeSum / this.dataSize;

        return similarity;

    }

    /**
     * Computes a type of similarity between this Uniform Fuzzy Hash and another one and returns it
     * as a number between 0 and 1.
     * 
     * @param other Another Uniform Fuzzy Hash.
     * @param similarityType The type of similarity.
     * @return A number between 0 and 1 representing the type of similarity between this Uniform
     *         Fuzzy Hash and the introduced one.
     */
    public double similarity(
            UniformFuzzyHash other,
            SimilarityTypes similarityType) {

        if (other == null) {
            throw new NullPointerException("The Uniform Fuzzy Hash is null.");
        }

        switch (similarityType) {

            case SIMILARITY:

                return this.similarity(other);

            case REVERSE_SIMILARITY:

                return other.similarity(this);

            default:

                double similarity = this.similarity(other);
                double reverse = other.similarity(this);

                switch (similarityType) {

                    case MAXIMUM:
                        return similarity >= reverse ? similarity : reverse;

                    case MINIMUM:
                        return similarity >= reverse ? reverse : similarity;

                    case ARITHMETIC_MEAN:
                        return (similarity + reverse) / 2;

                    case GEOMETRIC_MEAN:
                        return Math.sqrt(similarity * reverse);

                    default:
                        return similarity;

                }

        }

    }

    /**
     * Computes all the types of similarity between this Uniform Fuzzy Hash and another one.
     * 
     * @param other Another Uniform Fuzzy Hash.
     * @return Map of all the types of similarity between this Uniform Fuzzy Hash and another one.
     */
    public Map<SimilarityTypes, Double> similarities(
            UniformFuzzyHash other) {

        if (other == null) {
            throw new NullPointerException("The Uniform Fuzzy Hash is null.");
        }

        Map<SimilarityTypes, Double> similarities =
                new LinkedHashMap<>(SimilarityTypes.values().length);

        double similarity = this.similarity(other);
        double reverse = other.similarity(this);

        similarities.put(SimilarityTypes.SIMILARITY, similarity);
        similarities.put(SimilarityTypes.REVERSE_SIMILARITY, reverse);
        similarities.put(SimilarityTypes.MAXIMUM, similarity >= reverse ? similarity : reverse);
        similarities.put(SimilarityTypes.MINIMUM, similarity >= reverse ? reverse : similarity);
        similarities.put(SimilarityTypes.ARITHMETIC_MEAN, (similarity + reverse) / 2);
        similarities.put(SimilarityTypes.GEOMETRIC_MEAN, Math.sqrt(similarity * reverse));

        return similarities;

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

            if (this.blocks.size() != other.blocks.size()) {
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
        result = prime * result + blocks.size();

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
     * @return The list of blocks of this hash.
     */
    protected List<UniformFuzzyHashBlock> accessBlocks() {

        return blocks;

    }

    /**
     * @return The unmodifiable list of blocks of this hash.
     */
    public List<UniformFuzzyHashBlock> getBlocks() {

        return Collections.unmodifiableList(blocks);

    }

    /**
     * @return The set of blocks of this hash, building it if it is null.
     */
    protected Set<UniformFuzzyHashBlock> accessBlocksSet() {

        if (blocksSet == null) {
            blocksSet = new HashSet<>(blocks);
        }

        return blocksSet;

    }

    /**
     * @return The unmodifiable set of blocks of this hash.
     */
    public Set<UniformFuzzyHashBlock> getBlocksSet() {

        return Collections.unmodifiableSet(accessBlocksSet());

    }

    /**
     * Checks if a factor is valid to compute a Uniform Fuzzy Hash. In case it is not, an
     * IllegalArgumentException with a descriptive message is thrown.
     * 
     * @param factor Relation between data length and the hash mean number of blocks.
     *        Must be greater than 2 and must be odd.
     */
    public static void checkFactor(
            int factor) {

        if (factor <= 2) {
            throw new IllegalArgumentException("Factor must be greater than 2.");
        }

        if (factor % 2 == 0) {
            throw new IllegalArgumentException("Factor must be odd.");
        }

    }

    /**
     * @param number Any integer number.
     * @return The size in bytes of the number.
     */
    private static int sizeInBytes(
            int number) {

        return ((Integer.SIZE - Integer.numberOfLeadingZeros(number) - 1) / Byte.SIZE) + 1;

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
            ret = (ret << Byte.SIZE) % modulo;
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
