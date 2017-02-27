package securitybug.similarityuniformfuzzyhash;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * This class provides utility methods and constants to build string representations of Uniform
 * Fuzzy Hashes.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class ToStringUtils {

    /**
     * Separator between factor and blocks for a Uniform Fuzzy Hash string representation.
     */
    public static final String FACTOR_SEPARATOR = ":";

    /**
     * Separator between blocks for a Uniform Fuzzy Hash string representation.
     */
    public static final String BLOCKS_SEPARATOR = " ";

    /**
     * Separator between block parts for a Uniform Fuzzy Hash Block string representation.
     */
    public static final String BLOCK_INNER_SEPARATOR = "-";

    /**
     * String representing the format in which decimal numbers are printed.
     */
    public static final String DECIMALS_FORMAT_STR = "0.0##";

    /**
     * Format in which decimal numbers are printed.
     */
    public static final DecimalFormat DECIMALS_FORMAT = new DecimalFormat(DECIMALS_FORMAT_STR);

    /**
     * Maximum number of characters of an integer string representation.
     */
    protected static final int INT_MAX_CHARS =
            Integer.toString(Integer.MAX_VALUE).length();

    /**
     * Maximum number of characters of an integer hexadecimal string representation.
     */
    protected static final int HEX_INT_MAX_CHARS =
            Integer.toHexString(Integer.MAX_VALUE).length();

    /**
     * Hexadecimal base.
     */
    protected static final int HEX_RADIX = 16;


    /**
     * Enum of Uniform Fuzzy Hash characteristics.
     */
    public enum HashCharacteristics {

        /**
         * Factor.
         */
        FACTOR("Factor", "getFactor"),

        /**
         * Data size.
         */
        DATA_SIZE("Data Size", "getDataSize"),

        /**
         * Amount of blocks.
         */
        AMOUNT_OF_BLOCKS("Blocks", "getAmountOfBlocks"),

        /**
         * Block size mean.
         */
        BLOCK_SIZE_MEAN("BS Mean", "getBlockSizeMean"),

        /**
         * Block size standard deviation.
         */
        BLOCK_SIZE_ST_DEV("BS StDev", "getBlockSizeStDev"),

        /**
         * Hash.
         */
        HASH("Hash", "toString");

        /**
         * Characteristic name.
         */
        private String name;

        /**
         * Characteristic getter.
         */
        private String getter;

        /**
         * Constructor.
         * 
         * @param name The characteristic name.
         */
        HashCharacteristics(String name) {
            this.name = name;
            this.getter = null;
        }

        /**
         * Constructor.
         * 
         * @param name The characteristic name.
         * @param getter The characteristic getter.
         */
        HashCharacteristics(String name, String getter) {
            this.name = name;
            this.getter = getter;
        }

        /**
         * @return The characteristic name.
         */
        public String getName() {
            return name;
        }

        /**
         * @return The characteristic getter.
         */
        public String getGetter() {
            return getter;
        }

        /**
         * @param hash A Uniform Fuzzy Hash.
         * @return The hash invocation result of this characteristic getter.
         */
        public String getCharaceristicValue(UniformFuzzyHash hash) {

            if (hash == null) {
                throw new NullPointerException("Hash is null.");
            }

            if (getter == null) {
                throw new IllegalArgumentException("This characteristic has no getter.");
            }

            try {

                Object value = hash.getClass().getMethod(getter).invoke(hash);

                if (value instanceof Double || value instanceof Float) {
                    return DECIMALS_FORMAT.format(value);
                } else {
                    return value.toString();
                }

            } catch (Exception e) {
                throw new RuntimeException(String.format(
                        "Error invoking method %s",
                        getter));
            }

        }

        /**
         * @return A list with all the characteristics names.
         */
        public static List<String> names() {

            HashCharacteristics[] hashCharacteristics = HashCharacteristics.values();
            List<String> hashCharacteristicsNames =
                    new ArrayList<String>(hashCharacteristics.length);

            for (HashCharacteristics hashCharaceristic : hashCharacteristics) {
                hashCharacteristicsNames.add(hashCharaceristic.getName());
            }

            return hashCharacteristicsNames;

        }

    }

    /**
     * @param hash A Uniform Fuzzy Hash.
     * @return The maximum length of the hash string representation.
     */
    protected static int getHashMaxLength(UniformFuzzyHash hash) {

        int factorPartMaxLength = INT_MAX_CHARS + FACTOR_SEPARATOR.length();
        int blockMaxLength = 2 * HEX_INT_MAX_CHARS + BLOCK_INNER_SEPARATOR.length();

        return factorPartMaxLength + hash.getAmountOfBlocks() * blockMaxLength;

    }

    /**
     * Private constructor.
     */
    private ToStringUtils() {

    }

}
