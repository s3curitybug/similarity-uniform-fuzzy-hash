package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.spaces;

import org.apache.commons.io.IOUtils;
import org.fusesource.jansi.AnsiConsole;

import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * This class provides utility static methods to represent and compare Uniform Fuzzy Hashes in
 * visual way.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class VisualRepresentation {

    /**
     * Charset in which bases are encoded.
     */
    public static final Charset BASES_ENCODING = StandardCharsets.UTF_8;

    /**
     * Printable ASCII base.
     */
    public static final char[] PRINTABLE_ASCII_BASE = readBaseFromResources("printableAscii.base");

    /**
     * Default base.
     */
    public static final char[] DEFAULT_BASE = PRINTABLE_ASCII_BASE;

    /**
     * Default factor divisor.
     */
    public static final int DEFAULT_FACTOR_DIVISOR = 3;

    /**
     * Default line wrap.
     */
    public static final int DEFAULT_LINE_WRAP = 60;

    /**
     * Bases path inside resources.
     */
    private static final String RESOURCES_BASES_PATH = "/VisualPrint/";

    /**
     * Format in which accumulated wrap length per line will be formatted during a string wrap.
     */
    private static final String ACCUMULATED_WRAP_FORMAT = "%5s  %s";

    /**
     * Format in which percent accumulated wrap length per line will be formatted during a string
     * wrap.
     */
    private static final DecimalFormat ACCUMULATED_WRAP_DECIMAL_FORMAT = new DecimalFormat("0.0");

    /**
     * Unicode control character.
     */
    private static final char U_CTRL = '\u001b';

    /**
     * ANSI end character.
     */
    private static final char ANSI_END = 'm';

    /**
     * ANSI format which will be used to visually represent the blocks which are only present in the
     * first hash in a hashes comparison.
     */
    // Green Font Color.
    private static final String BLOCK_IN_FIRST_HASH_ANSI = U_CTRL + "[32" + ANSI_END;

    /**
     * ANSI format will be used to visually represent the blocks which are only present in the
     * second hash in a hashes comparison.
     */
    // Blue FontColor.
    private static final String BLOCK_IN_SECOND_HASH_ANSI = U_CTRL + "[34" + ANSI_END;

    /**
     * ANSI format which will be used to visually represent the blocks which are present in both
     * hashes in a hashes comparison.
     */
    // Red Font Color.
    private static final String BLOCK_IN_BOTH_HASHES_ANSI = U_CTRL + "[31" + ANSI_END;

    /**
     * ANSI format reset.
     */
    private static final String ANSI_RESET = U_CTRL + "[0" + ANSI_END;

    /**
     * Private constructor.
     */
    private VisualRepresentation() {

    }

    /**
     * Represents a Uniform Fuzzy Hash in a visual way, using the default base and factor divisor.
     * 
     * @param hash The Uniform Fuzzy Hash.
     * @return A string representing the introduced Uniform Fuzzy Hash in a visual way.
     */
    public static String represent(
            UniformFuzzyHash hash) {

        return represent(hash, DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR);

    }

    /**
     * Represents a Uniform Fuzzy Hash in a visual way.
     * 
     * @param hash The Uniform Fuzzy Hash.
     * @param base The characters base which will be used to represent the blocks.
     * @param factorDivisor Amount of characters per factor size for each block.
     * @return A string representing the introduced Uniform Fuzzy Hash in a visual way.
     */
    public static String represent(
            UniformFuzzyHash hash,
            char[] base,
            int factorDivisor) {

        if (hash == null) {
            throw new NullPointerException("Hash is null.");
        }

        if (base == null) {
            throw new NullPointerException("Base is null.");
        }

        if (base.length == 0) {
            throw new IllegalArgumentException("Base is empty.");
        }

        if (factorDivisor < 1) {
            throw new IllegalArgumentException("Factor divisor is lower than 1.");
        }

        int factor = hash.getFactor();
        List<UniformFuzzyHashBlock> blocks = hash.getBlocks();

        StringBuilder strB = new StringBuilder(blocks.size() * factorDivisor * 2);

        for (UniformFuzzyHashBlock block : blocks) {

            char character = base[block.getBlockHash() % base.length];
            int blockSize = block.getBlockSize();

            long characterRepetitions = 0;
            do {
                strB.append(character);
            } while (blockSize > (++characterRepetitions * factor + factor / 2) / factorDivisor);

        }

        return strB.toString();

    }

    /**
     * Represents a Uniform Fuzzy Hash in a visual way, coloring the blocks which are present in
     * another Uniform Fuzzy Hash with a different color to the ones which are not, and using the
     * default base and factor divisor.
     * 
     * @param hash1 The Uniform Fuzzy Hash.
     * @param hash2 The Uniform Fuzzy Hash to which the first one will be compared.
     * @return A string representing the introduced Uniform Fuzzy Hash in a visual way, with ANSI
     *         color characters.
     */
    public static String representCompared(
            UniformFuzzyHash hash1,
            UniformFuzzyHash hash2) {

        return representCompared(hash1, hash2, DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR);

    }

    /**
     * Represents a Uniform Fuzzy Hash in a visual way, coloring the blocks which are present in
     * another Uniform Fuzzy Hash with a different color to the ones which are not.
     * 
     * @param hash1 The Uniform Fuzzy Hash.
     * @param hash2 The Uniform Fuzzy Hash to which the first one will be compared.
     * @param base The characters base which will be used to represent the blocks.
     * @param factorDivisor Amount of characters per factor size for each block.
     * @return A string representing the introduced Uniform Fuzzy Hash in a visual way, with ANSI
     *         color characters.
     */
    public static String representCompared(
            UniformFuzzyHash hash1,
            UniformFuzzyHash hash2,
            char[] base,
            int factorDivisor) {

        if (hash1 == null) {
            throw new NullPointerException("Hash 1 is null.");
        }

        if (hash2 == null) {
            throw new NullPointerException("Hash 2 is null.");
        }

        if (base == null) {
            throw new NullPointerException("Base is null.");
        }

        if (base.length == 0) {
            throw new IllegalArgumentException("Base is empty.");
        }

        if (factorDivisor < 1) {
            throw new IllegalArgumentException("Factor divisor is lower than 1.");
        }

        int factor1 = hash1.getFactor();
        int factor2 = hash2.getFactor();

        if (factor1 != factor2) {
            throw new IllegalArgumentException("The Uniform Fuzzy Hashes factors are different.");
        }

        List<UniformFuzzyHashBlock> blocks1 = hash1.getBlocks();
        Set<UniformFuzzyHashBlock> blocks2 = hash2.getBlocksSet();

        StringBuilder strB = new StringBuilder(blocks1.size() * factorDivisor * 2);

        String color = null;
        for (UniformFuzzyHashBlock block : blocks1) {

            char character = base[block.getBlockHash() % base.length];
            int blockSize = block.getBlockSize();

            if (blocks2.contains(block)) {
                if (!BLOCK_IN_BOTH_HASHES_ANSI.equals(color)) {
                    color = BLOCK_IN_BOTH_HASHES_ANSI;
                    strB.append(ANSI_RESET);
                    strB.append(BLOCK_IN_BOTH_HASHES_ANSI);
                }
            } else {
                if (!BLOCK_IN_FIRST_HASH_ANSI.equals(color)) {
                    color = BLOCK_IN_FIRST_HASH_ANSI;
                    strB.append(ANSI_RESET);
                    strB.append(BLOCK_IN_FIRST_HASH_ANSI);
                }
            }

            long characterRepetitions = 0;
            do {
                strB.append(character);
            } while (blockSize > (++characterRepetitions * factor1 + factor1 / 2) / factorDivisor);

        }

        strB.append(ANSI_RESET);

        return strB.toString();

    }

    /**
     * Prints a Uniform Fuzzy Hash in a visual way, using the default base, factor divisor and line
     * wrap.
     * 
     * @param hash The Uniform Fuzzy Hash.
     */
    public static void print(
            UniformFuzzyHash hash) {

        print(hash, DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR, DEFAULT_LINE_WRAP, true);

    }

    /**
     * Prints a Uniform Fuzzy Hash in a visual way.
     * 
     * @param hash The Uniform Fuzzy Hash.
     * @param base The characters base which will be used to represent the blocks.
     * @param factorDivisor Amount of characters per factor size for each block.
     * @param lineWrap Amount of characters per line. If this argument is lower than 1, no line wrap
     *        is performed and the full representation is printed in one line.
     * @param concatenatePercent In case line wrap is performed, true to concatenate to each line
     *        its relative percent to the total length.
     */
    public static void print(
            UniformFuzzyHash hash,
            char[] base,
            int factorDivisor,
            int lineWrap,
            boolean concatenatePercent) {

        String representation = represent(hash, base, factorDivisor);
        List<String> wrappedRepresentation =
                wrapString(representation, lineWrap, concatenatePercent);

        System.out.println();

        for (String line : wrappedRepresentation) {
            System.out.println(line);
        }

        System.out.println();

    }

    /**
     * Prints a Uniform Fuzzy Hash in a visual way, coloring the blocks which are present in another
     * Uniform Fuzzy Hash with a different color to the ones which are not, and using the default
     * base, factor divisor, and line wrap.
     * 
     * @param hash1 The Uniform Fuzzy Hash.
     * @param hash2 The Uniform Fuzzy Hash to which the first one will be compared.
     */
    public static void printCompared(
            UniformFuzzyHash hash1,
            UniformFuzzyHash hash2) {

        printCompared(hash1, hash2, DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR, DEFAULT_LINE_WRAP, true);

    }

    /**
     * Prints a Uniform Fuzzy Hash in a visual way, coloring the blocks which are present in another
     * Uniform Fuzzy
     * Hash with a different color to the ones which are not.
     * 
     * @param hash1 The Uniform Fuzzy Hash.
     * @param hash2 The Uniform Fuzzy Hash to which the first one will be compared.
     * @param base The characters base which will be used to represent the blocks.
     * @param factorDivisor Amount of characters per factor size for each block.
     * @param lineWrap Amount of characters per line. If this argument is lower than 1, no line wrap
     *        is performed and the full representation is printed in one line.
     * @param concatenatePercent In case line wrap is performed, true to concatenate to each line
     *        its relative percent to the total length.
     */
    public static void printCompared(
            UniformFuzzyHash hash1,
            UniformFuzzyHash hash2,
            char[] base,
            int factorDivisor,
            int lineWrap,
            boolean concatenatePercent) {

        String representation1 = representCompared(hash1, hash2, base, factorDivisor);
        String representation2 = representCompared(hash2, hash1, base, factorDivisor)
                .replace(BLOCK_IN_FIRST_HASH_ANSI, BLOCK_IN_SECOND_HASH_ANSI);

        List<String> wrappedRepresentation1 =
                wrapStringRespectingAnsiFormat(representation1, lineWrap, concatenatePercent);
        List<String> wrappedRepresentation2 =
                wrapStringRespectingAnsiFormat(representation2, lineWrap, concatenatePercent);

        String wrapLengthSpaces = concatenatePercent
                ? spaces(lineWrap + formatAccumulatedWrapLength("", 0).length())
                : spaces(lineWrap);
        while (wrappedRepresentation1.size() < wrappedRepresentation2.size()) {
            wrappedRepresentation1.add(wrapLengthSpaces);
        }
        while (wrappedRepresentation2.size() < wrappedRepresentation1.size()) {
            wrappedRepresentation2.add(wrapLengthSpaces);
        }

        System.out.println();

        AnsiConsole.systemInstall();

        Iterator<String> iterator1 = wrappedRepresentation1.iterator();
        Iterator<String> iterator2 = wrappedRepresentation2.iterator();
        final int separation = 5;
        while (iterator1.hasNext()) {
            AnsiConsole.out.println(iterator1.next() + spaces(separation) + iterator2.next());
        }

        AnsiConsole.systemUninstall();

        System.out.println();

    }

    /**
     * Reads a base from RESOURCES_BASES_PATH.
     * Must be encoded as BASES_ENCODING.
     * 
     * @param baseName The base name.
     * @return The base as a char[].
     */
    private static char[] readBaseFromResources(
            String baseName) {

        if (baseName == null) {
            throw new NullPointerException("Base name is null.");
        }

        URL resource = VisualRepresentation.class.getResource(RESOURCES_BASES_PATH + baseName);
        if (resource == null) {
            throw new IllegalArgumentException("Base name does not match any resource.");
        }

        try {
            return IOUtils.toString(resource, BASES_ENCODING).toCharArray();
        } catch (Exception exception) {
            throw new RuntimeException(
                    String.format("Error reading base %s from resources", baseName),
                    exception);
        }

    }

    /**
     * Splits a string in fixed length substrings.
     * The last substring is filled with spaces until reaching the fixed length.
     * 
     * @param string The string to split.
     * @param wrapLength The substrings length. If this argument is lower than 1, no split is
     *        performed.
     * @param concatenatePercent True to concatenate to each line its relative percent to the total
     *        string length.
     * @return A List of strings containing the substrings, or a List of strings containing the
     *         introduced string if wrapLength is lower than 1.
     */
    private static List<String> wrapString(
            String string,
            int wrapLength,
            boolean concatenatePercent) {

        if (string == null) {
            throw new NullPointerException("String is null.");
        }

        List<String> wrappedString = new LinkedList<String>();
        double relativeWrapLength = (double) wrapLength / string.length();
        double accumulatedWrapLength = 0;

        if (wrapLength < 1) {

            wrappedString.add(string);

        } else {

            while (string.length() > wrapLength) {

                if (concatenatePercent) {
                    wrappedString.add(formatAccumulatedWrapLength(
                            string.substring(0, wrapLength),
                            accumulatedWrapLength));
                } else {
                    wrappedString.add(string.substring(0, wrapLength));
                }

                string = string.substring(wrapLength);
                accumulatedWrapLength += relativeWrapLength;

            }

            if (concatenatePercent) {
                wrappedString.add(formatAccumulatedWrapLength(
                        string + spaces(wrapLength - string.length()),
                        accumulatedWrapLength));
            } else {
                wrappedString.add(string + spaces(wrapLength - string.length()));
            }

        }

        return wrappedString;

    }

    /**
     * Splits a string in fixed length substrings.
     * ANSI format is respected.
     * The last substring is filled with spaces until reaching the fixed length.
     * 
     * @param string The string to split.
     * @param wrapLength The substrings length. If this argument is lower than 1, no split is
     *        performed.
     * @param concatenatePercent True to concatenate to each line its relative percent to the total
     *        string length.
     * @return A List of strings containing the substrings, or a List of strings containing the
     *         introduced string if wrapLength is lower than 1.
     */
    private static List<String> wrapStringRespectingAnsiFormat(
            String string,
            int wrapLength,
            boolean concatenatePercent) {

        if (string == null) {
            throw new NullPointerException("String is null.");
        }

        List<String> wrappedString = new LinkedList<String>();
        double relativeWrapLength =
                (double) wrapLength / string.replaceAll(U_CTRL + ".+?" + ANSI_END, "").length();
        double accumulatedWrapLength = 0;

        if (wrapLength < 1) {

            wrappedString.add(string);

        } else {

            StringBuilder substring = new StringBuilder(wrapLength * 2);
            StringBuilder ansiFormat = new StringBuilder();
            int substringChars = 0;

            for (int i = 0; i < string.length(); i++) {

                char ch = string.charAt(i);

                if (ch == U_CTRL) {

                    ansiFormat = new StringBuilder();
                    while (string.charAt(i) != ANSI_END) {
                        ansiFormat.append(string.charAt(i++));
                    }
                    ansiFormat.append(string.charAt(i));

                    substring.append(ansiFormat);

                } else {

                    substring.append(ch);
                    substringChars++;

                    if (substringChars == wrapLength || i == string.length() - 1) {

                        if (ansiFormat.length() > 0 && !ansiFormat.toString().equals(ANSI_RESET)) {

                            substring.append(ANSI_RESET);

                            if (concatenatePercent) {
                                wrappedString.add(formatAccumulatedWrapLength(
                                        substring.toString(),
                                        accumulatedWrapLength));
                            } else {
                                wrappedString.add(substring.toString());
                            }

                            substring = new StringBuilder(wrapLength * 2);
                            substring.append(ansiFormat);

                        } else {

                            if (concatenatePercent) {
                                wrappedString.add(formatAccumulatedWrapLength(
                                        substring.toString(),
                                        accumulatedWrapLength));
                            } else {
                                wrappedString.add(substring.toString());
                            }

                            substring = new StringBuilder(wrapLength * 2);

                        }

                        accumulatedWrapLength += relativeWrapLength;
                        substringChars = 0;

                    }

                }

            }

            if (substring.length() > 0) {

                if (ansiFormat.length() > 0 && !ansiFormat.toString().equals(ANSI_RESET)) {
                    substring.append(ANSI_RESET);
                }

                substring.append(spaces(wrapLength - substringChars));

                if (concatenatePercent) {
                    wrappedString.add(formatAccumulatedWrapLength(
                            substring.toString(),
                            accumulatedWrapLength));
                } else {
                    wrappedString.add(substring.toString());
                }

            }

        }

        return wrappedString;

    }

    /**
     * Formats a wrapped line concatenating its percent accumulated wrap length to it.
     * 
     * @param string The wrapped line.
     * @param accumulatedWrapLength Accumulated wrap length in previous lines.
     * @return The wrapped line formatted with its percent accumulated wrap length.
     */
    private static String formatAccumulatedWrapLength(
            String string,
            double accumulatedWrapLength) {

        final int percent = 100;

        return String.format(
                ACCUMULATED_WRAP_FORMAT,
                ACCUMULATED_WRAP_DECIMAL_FORMAT.format(accumulatedWrapLength * percent),
                string);

    }

}
