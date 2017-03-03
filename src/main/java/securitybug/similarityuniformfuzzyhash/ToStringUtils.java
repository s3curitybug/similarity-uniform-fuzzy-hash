package securitybug.similarityuniformfuzzyhash;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
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
     * Charset for reading and writing files of Uniform Fuzzy Hashes.
     */
    public static final Charset UFH_FILES_ECONDING = StandardCharsets.UTF_8;

    /**
     * Mark at the beginning of a Uniform Fuzzy Hash file line which indicates that the line should
     * be ignored.
     */
    public static final String IGNORE_MARK = "#";

    /**
     * Separator between name and hash for a named Uniform Fuzzy Hash string representation.
     */
    public static final String NAME_SEPARATOR = " > ";

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
     * Tabulation.
     */
    public static final String TAB = "   ";

    /**
     * Length at which names will be truncated in table prints.
     * If this number is lower than 1, no truncation is performed.
     */
    public static final int NAME_TRUNCATE_LENGTH = 8;

    /**
     * String which will be used when a name is null.
     */
    public static final String NULL_NAME = "null";

    /**
     * String which will be used when a name is empty.
     */
    public static final String EMPTY_NAME = "-";

    /**
     * String which will be used when a value is null.
     */
    public static final String NULL_VALUE = "-";

    /**
     * String which will be used when a hash name is null or empty.
     */
    public static final String NULL_OR_EMPTY_HASH_NAME = "Hash";

    /**
     * Hash name to hashes string.
     */
    public static final String HASH_TO_HASHES_STR = "%s -> Hashes";

    /**
     * Hashes to hash name string.
     */
    public static final String HASHES_TO_HASH_STR = "Hashes -> %s";

    /**
     * String representing the format in which decimal numbers are printed.
     */
    public static final String DECIMALS_FORMAT_STR = "0.0##";

    /**
     * Format in which decimal numbers are printed.
     */
    public static final DecimalFormat DECIMALS_FORMAT = new DecimalFormat(DECIMALS_FORMAT_STR);

    /**
     * Hexadecimal base.
     */
    protected static final int HEX_RADIX = 16;

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
         * @param getter The characteristic getter.
         */
        HashCharacteristics(
                String name,
                String getter) {

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
        public String getCharaceristicValue(
                UniformFuzzyHash hash) {

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
     * Private constructor.
     */
    private ToStringUtils() {

    }

    /**
     * @param hash A Uniform Fuzzy Hash.
     * @return The maximum length of the hash string representation.
     */
    protected static int getHashMaxLength(
            UniformFuzzyHash hash) {

        int factorPartMaxLength = INT_MAX_CHARS + FACTOR_SEPARATOR.length();
        int blockMaxLength = 2 * HEX_INT_MAX_CHARS + BLOCK_INNER_SEPARATOR.length();

        return factorPartMaxLength + hash.getAmountOfBlocks() * blockMaxLength;

    }

    /**
     * Checks a name.
     * 
     * @param name The name to check.
     * @param truncateLength Maximum length of the returned name.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return NULL_NAME if the name is null, EMPTY_NAME if the name is empty after trimming it, or
     *         the original name trimmed and truncated to truncateLength otherwise.
     */
    protected static String checkName(
            String name,
            int truncateLength) {

        if (name == null) {
            return NULL_NAME;
        }

        name = name.trim();

        if (name.isEmpty()) {
            return EMPTY_NAME;
        }

        if (truncateLength > 0 && name.length() > truncateLength) {
            name = name.substring(0, truncateLength);
        }

        return name;

    }

    /**
     * Checks a hash name.
     * 
     * @param hashName The hash name to check.
     * @param truncateLength Maximum length of the returned name.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return NULL_OR_EMPTY_HASH_NAME if the hash name is null or empty after trimming it, or the
     *         original hash name trimmed otherwise.
     */
    protected static String checkHashName(
            String hashName,
            int truncateLength) {

        if (hashName == null) {
            hashName = NULL_OR_EMPTY_HASH_NAME;
        }

        hashName = hashName.trim();

        if (hashName.isEmpty()) {
            return NULL_OR_EMPTY_HASH_NAME;
        }

        if (truncateLength > 0 && hashName.length() > truncateLength) {
            hashName = hashName.substring(0, truncateLength);
        }

        return hashName;

    }

    /**
     * @param checkNames True to check the Strings as names before computing their length.
     * @param truncateLength Introduce a number larger than 0 to truncate the Strings to a maximum
     *        length.
     * @param strings Collection of Strings.
     * @return The length of the longest String within the introduced collection.
     */
    protected static int getMaxLength(
            boolean checkNames,
            int truncateLength,
            Collection<String> strings) {

        int maxLength = 0;

        for (String string : strings) {

            if (checkNames) {
                string = checkName(string, truncateLength);
            } else if (string == null) {
                continue;
            }

            if (string.length() > maxLength) {
                maxLength = string.length();
            }

        }

        return maxLength;

    }

    /**
     * @param checkNames True to check the Strings as names before computing their length.
     * @param truncateLength Introduce a number larger than 0 to truncate the Strings to a maximum
     *        length.
     * @param strings Varargs of Strings.
     * @return The length of the longest String within the introduced varargs.
     */
    protected static int getMaxLength(
            boolean checkNames,
            int truncateLength,
            String... strings) {

        return getMaxLength(checkNames, truncateLength, Arrays.asList(strings));

    }

    /**
     * @param string A string to be repeated.
     * @param n Amount of repetitions.
     * @return A string formed by the repetition of the introduced string n times.
     */
    protected static String repeatString(
            String string,
            int n) {

        if (n < 1) {
            return "";
        }

        StringBuilder stringBuilder = new StringBuilder(string.length() * n);

        for (int i = 0; i < n; i++) {
            stringBuilder.append(string);
        }

        return stringBuilder.toString();

    }

    /**
     * @param n Amount of spaces.
     * @return A string composed of n spaces.
     */
    protected static String spaces(
            int n) {

        return repeatString(" ", n);

    }

    /**
     * @param n Amount of hyphens.
     * @return A string composed of n hyphens.
     */
    protected static String hyphens(
            int n) {

        return repeatString("-", n);

    }

}
