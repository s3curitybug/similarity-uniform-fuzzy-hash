package com.github.s3curitybug.similarityuniformfuzzyhash;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
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
     * Separator between identifier and hash for an identified Uniform Fuzzy Hash string
     * representation.
     */
    public static final String IDENTIFIER_SEPARATOR = " > ";

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
    public static final String BLOCK_INNER_SEPARATOR = "/";

    /**
     * Tabulation.
     */
    public static final String TAB = "   ";

    /**
     * New line.
     */
    public static final String NEW_LINE = System.getProperty("line.separator");

    /**
     * String which will be used when an identifier is null.
     */
    public static final String NULL_IDENTIFIER = "null";

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
     * Maximum number of characters of an integer string representation.
     */
    protected static final int INT_MAX_CHARS =
            Integer.toString(Integer.MAX_VALUE).length();

    /**
     * Maximum number of characters of a factor string representation with separator.
     */
    protected static final int FACTOR_WITH_SEP_MAX_CHARS =
            INT_MAX_CHARS + FACTOR_SEPARATOR.length();

    /**
     * Base in which Uniform Fuzzy Hash Blocks integers are represented.
     */
    protected static final int BLOCK_BASE = 36;

    /**
     * Maximum number of characters of an integer block base representation.
     */
    protected static final int BLOCK_INT_MAX_CHARS =
            Integer.toString(Integer.MAX_VALUE, BLOCK_BASE).length();

    /**
     * Maximum number of characters of a block string representation.
     */
    protected static final int BLOCK_MAX_CHARS =
            2 * BLOCK_INT_MAX_CHARS + BLOCK_INNER_SEPARATOR.length();

    /**
     * Maximum number of characters of a block string representation with separator.
     */
    protected static final int BLOCK_WITH_SEP_MAX_CHARS =
            BLOCK_MAX_CHARS + BLOCKS_SEPARATOR.length();

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
     * ANSI code color which will be used to mark decimals which are above a threshold.
     */
    private static final AnsiCodeColors ANSI_CODE_COLOR_DECIMAL_ABOVE = AnsiCodeColors.RED_FONT;

    /**
     * ANSI code color which will be used to mark decimals which are below a threshold.
     */
    private static final AnsiCodeColors ANSI_CODE_COLOR_DECIMAL_BELOW = AnsiCodeColors.BLUE_FONT;

    /**
     * Private constructor.
     */
    private ToStringUtils() {

    }

    /**
     * @param strings Collection of strings.
     * @return Maximum length between the strings in the collection.
     */
    protected static int maxLength(
            Collection<String> strings) {

        int maxLength = 0;

        for (String string : strings) {
            if (string != null && string.length() > maxLength) {
                maxLength = string.length();
            }
        }

        return maxLength;

    }

    /**
     * Converts an identifier to string and prepares it to be printed.
     * 
     * @param <T> Identifier type.
     * @param identifier The identifier.
     * @param truncateLength Maximum length of the returned string.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return The identifier prepared to be printed.
     */
    protected static <T> String prepareIdentifier(
            T identifier,
            int truncateLength) {

        String preparedIdentifier = null;

        if (identifier == null) {
            preparedIdentifier = NULL_IDENTIFIER;
        } else {
            preparedIdentifier = identifier.toString();
        }

        preparedIdentifier = preparedIdentifier.trim();

        if (truncateLength > 0 && preparedIdentifier.length() > truncateLength) {
            preparedIdentifier = preparedIdentifier.substring(0, truncateLength);
        }

        return preparedIdentifier;

    }

    /**
     * Prepares a collection of identifiers to be printed.
     * 
     * @param <T> Identifiers type.
     * @param identifiers The collection of identifiers.
     * @param truncateLength Maximum length of the returned string.
     *        If this parameter is lower than 1, no truncation is performed.
     * @return The list of identifiers prepared to be printed.
     */
    protected static <T> List<String> prepareIdentifiers(
            Collection<T> identifiers,
            int truncateLength) {

        List<String> preparedIdentifiers = new ArrayList<>(identifiers.size());

        for (T identifier : identifiers) {
            String preparedIdentifier = prepareIdentifier(identifier, truncateLength);
            preparedIdentifiers.add(preparedIdentifier);
        }

        return preparedIdentifiers;

    }

    /**
     * Formats a decimal number.
     * 
     * @param decimal A decimal number.
     * @return The formatted decimal number.
     */
    public static String formatDecimal(
            Double decimal) {

        if (decimal == null) {
            return NULL_VALUE;
        }

        return DECIMALS_FORMAT.format(decimal);

    }

    /**
     * Formats a decimal number, marking it with a color if it is above or equal to a threshold, and
     * with another color if it is below another threshold.
     * 
     * @param decimal A decimal number.
     * @param markAbove Mark the decimal with a color if it is above or equal to this threshold.
     *        Introduce a negative number to not mark the decimal.
     * @param markBelow Mark the decimal with a color if it is below this threshold.
     *        Introduce a negative number to not mark the decimal.
     * @return The formatted and possibly marked decimal number.
     */
    public static String formatDecimal(
            Double decimal,
            double markAbove,
            double markBelow) {

        if (decimal == null) {
            return NULL_VALUE;
        }

        String decimalStr = formatDecimal(decimal);

        if (markAbove >= 0 && decimal >= markAbove) {
            decimalStr = ANSI_CODE_COLOR_DECIMAL_ABOVE.getCode()
                    + decimalStr
                    + AnsiCodeColors.RESET.getCode();
        } else if (markBelow >= 0 && decimal < markBelow) {
            decimalStr = ANSI_CODE_COLOR_DECIMAL_BELOW.getCode()
                    + decimalStr
                    + AnsiCodeColors.RESET.getCode();
        }

        return decimalStr;

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
