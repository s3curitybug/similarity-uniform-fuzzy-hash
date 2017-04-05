package securitybug.similarityuniformfuzzyhash;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Collection;
import java.util.Locale;

/**
 * This class provides utility methods and constants to build string representations of Uniform
 * Fuzzy Hashes.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class ToStringUtils {

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
     * New line.
     */
    public static final String NEW_LINE = System.getProperty("line.separator");

    /**
     * String which will be used when a name is null.
     */
    public static final String NULL_NAME = "null";

    /**
     * String which will be used when a value is null.
     */
    public static final String NULL_VALUE = "-";

    /**
     * Separator for comma separated values.
     */
    public static final String CSV_SEPARATOR = ", ";

    /**
     * Symbols for decimal numbers format.
     */
    public static final DecimalFormatSymbols DECIMALS_FORMAT_SYMBOLS =
            DecimalFormatSymbols.getInstance(Locale.ROOT);

    /**
     * Format in which decimal numbers are printed.
     */
    public static final DecimalFormat DECIMALS_FORMAT =
            new DecimalFormat("0.0##", DECIMALS_FORMAT_SYMBOLS);

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
     * Maximum number of characters of a decimal number string representation.
     */
    protected static final int DECIMAL_MAX_CHARS = 1
            + INT_MAX_CHARS
            + DECIMALS_FORMAT.getMaximumFractionDigits();

    /**
     * Maximum number of characters of a 0-1 decimal number string representation.
     */
    protected static final int ZERO_TO_ONE_DECIMAL_MAX_CHARS = 1
            + DECIMALS_FORMAT.getMinimumIntegerDigits()
            + DECIMALS_FORMAT.getMaximumFractionDigits();

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
     * @param truncateNameLength Maximum length of the returned name.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return NULL_NAME if the name is null, EMPTY_NAME if the name is empty after trimming it, or
     *         the original name trimmed and truncated to truncateNameLength otherwise.
     */
    protected static String checkName(
            String name,
            int truncateNameLength) {

        if (name == null) {
            name = NULL_NAME;
        }

        name = name.trim();

        if (truncateNameLength > 0 && name.length() > truncateNameLength) {
            name = name.substring(0, truncateNameLength);
        }

        return name;

    }

    /**
     * @param checkNames True to check the Strings as names before computing their length.
     * @param truncateNameLength In case Strings are checked as names, introduce a number larger
     *        than 0 to truncate the Strings to a maximum length.
     * @param strings Collection of Strings.
     * @return The length of the longest String within the introduced collection.
     */
    protected static int getMaxLength(
            boolean checkNames,
            int truncateNameLength,
            Collection<String> strings) {

        int maxLength = 0;

        for (String string : strings) {

            if (checkNames) {
                string = checkName(string, truncateNameLength);
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
