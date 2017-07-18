package com.github.s3curitybug.similarityuniformfuzzyhash;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * This class provides utility methods and constants to build string representations of Uniform
 * Fuzzy Hashes.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class ToStringUtils {

    /**
     * Charset for reading and writing files.
     */
    public static final Charset FILES_ENCODING = StandardCharsets.UTF_8;

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
    public static final String BLOCKS_SEPARATOR = "-";

    /**
     * Separator between block parts for a Uniform Fuzzy Hash Block string representation.
     */
    public static final String BLOCK_INNER_SEPARATOR = ".";

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
     * Trimmed separator for comma separated values.
     */
    public static final String CSV_TRIMMED_SEPARATOR = CSV_SEPARATOR.trim();

    /**
     * Quotation mark for comma separated values.
     */
    public static final String CSV_QUOTATION_MARK = "\"";

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
     * Maximum number of characters of a factor string representation with separator.
     */
    protected static final int FACTOR_WITH_SEP_MAX_CHARS =
            INT_MAX_CHARS + FACTOR_SEPARATOR.length();

    /**
     * Maximum number of characters of a block hexadecimal string representation.
     */
    protected static final int HEX_BLOCK_MAX_CHARS =
            2 * HEX_INT_MAX_CHARS + BLOCK_INNER_SEPARATOR.length();

    /**
     * Maximum number of characters of a block hexadecimal string representation with separator.
     */
    protected static final int HEX_BLOCK_WITH_SEP_MAX_CHARS =
            HEX_BLOCK_MAX_CHARS + BLOCKS_SEPARATOR.length();

    /**
     * Number of bits of an ascii character.
     */
    protected static final int ASCII_CHAR_BITS = 7;

    /**
     * Maximum number of characters of an integer ascii string representation, including escapes and
     * number of characters.
     */
    protected static final int ASCII_INT_MAX_CHARS =
            2 * ((Integer.SIZE / ASCII_CHAR_BITS) + 2);

    /**
     * Maximum number of characters of a block ascii string representation.
     */
    protected static final int ACII_BLOCK_MAX_CHARS =
            2 * ASCII_INT_MAX_CHARS;

    /**
     * Character encoder for ascii string representations.
     */
    protected static final int ASCII_CHAR_ENCODER =
            (1 << ASCII_CHAR_BITS) - 1; // 0b01111111

    /**
     * Number of bits needed to store the maximum number of characters of an integer ascii string
     * representation, including escapes and number of characters.
     */
    protected static final int ASCII_INT_MAX_CHARS_BITS =
            Integer.SIZE - Integer.numberOfLeadingZeros(ASCII_INT_MAX_CHARS); // 4

    /**
     * Number of bits to shift the number of characters of an integer ascii string representation.
     */
    protected static final int ASCII_INT_CHARS_SHIFT_BITS =
            ASCII_CHAR_BITS - ASCII_INT_MAX_CHARS_BITS; // 3

    /**
     * Number of characters of an integer ascii string representation encoder.
     */
    protected static final int ASCII_INT_CHARS_ENCODER =
            (1 << ASCII_INT_CHARS_SHIFT_BITS) - 1; // 0b00000111

    /**
     * Escapable characters for ascii string representations.
     */
    protected static final List<Character> ASCII_ESCAPABLE_CHARS = Arrays.asList(
            '\\', '\0', '\r', '\n',
            NAME_SEPARATOR.trim().charAt(0),
            FACTOR_SEPARATOR.charAt(0));

    /**
     * Escape character for ascii string representations.
     */
    protected static final char ASCII_ESCAPE_CHAR = '\\';

    /**
     * Unicode control character.
     */
    protected static final char UNICODE_CTRL = '\u001b';

    /**
     * ANSI code start character.
     */
    protected static final char ANSI_CODE_START = '[';

    /**
     * ANSI code color end character.
     */
    protected static final char ANSI_CODE_COLOR_END = 'm';

    /**
     * ANSI code color pattern.
     */
    protected static final Pattern ANSI_CODE_COLOR_PATTERN =
            Pattern.compile(UNICODE_CTRL + ".+?" + ANSI_CODE_COLOR_END);

    /**
     * Enum of ANSI code colors.
     */
    protected enum AnsiCodeColors {

        /**
         * Red font color.
         */
        RED_FONT(31),

        /**
         * Green font color.
         */
        GREEN_FONT(32),

        /**
         * Blue font color.
         */
        BLUE_FONT(34),

        /**
         * Reset color.
         */
        RESET(0);

        /**
         * Color number.
         */
        private int number;

        /**
         * Color code.
         */
        private String code;

        /**
         * Constructor.
         * 
         * @param number Color number.
         */
        AnsiCodeColors(
                int number) {

            this.number = number;
            this.code = Character.toString(UNICODE_CTRL)
                    + Character.toString(ANSI_CODE_START)
                    + Integer.toString(number)
                    + Character.toString(ANSI_CODE_COLOR_END);

        }

        /**
         * @return The color number.
         */
        protected int getNumber() {
            return number;
        }

        /**
         * @return The color code.
         */
        protected String getCode() {
            return code;
        }

        /**
         * Removes all ANSI code colors from a string.
         * 
         * @param string A string.
         * @return The string without any ANSI code colors.
         */
        protected static String remove(
                String string) {

            return ANSI_CODE_COLOR_PATTERN.matcher(string).replaceAll("");

        }

    }

    /**
     * Private constructor.
     */
    private ToStringUtils() {

    }

    /**
     * Checks a name.
     * 
     * @param name The name to check.
     * @param truncateNameLength Maximum length of the returned name.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return NULL_NAME if the name is null, or the original name trimmed and truncated to
     *         truncateNameLength otherwise.
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

        StringBuilder strB = new StringBuilder(string.length() * n);

        for (int i = 0; i < n; i++) {
            strB.append(string);
        }

        return strB.toString();

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

    /**
     * Escapes a string to include it into a comma separated values list.
     * 
     * @param str The string to escape.
     * @return The escaped string.
     */
    protected static String escapeCsv(
            String str) {

        if (str.contains(CSV_TRIMMED_SEPARATOR) || str.contains(CSV_QUOTATION_MARK)) {

            return CSV_QUOTATION_MARK
                    + str.replace(CSV_QUOTATION_MARK, CSV_QUOTATION_MARK + CSV_QUOTATION_MARK)
                    + CSV_QUOTATION_MARK;

        } else {

            return str;

        }

    }

}
