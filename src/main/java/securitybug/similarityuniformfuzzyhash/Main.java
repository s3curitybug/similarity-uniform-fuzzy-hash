package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.DECIMALS_FORMAT;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.IGNORE_MARK;
import static securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.DEFAULT_SIMILARITY_SORT_CRITERIA;
import static securitybug.similarityuniformfuzzyhash.VisualRepresentation.DEFAULT_BASE;
import static securitybug.similarityuniformfuzzyhash.VisualRepresentation.DEFAULT_FACTOR_DIVISOR;
import static securitybug.similarityuniformfuzzyhash.VisualRepresentation.DEFAULT_LINE_WRAP;

import securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.SimilaritySortCriterias;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class provides a main method to run the Uniform Fuzzy Hash jar via command line.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class Main {

    /**
     * Default jar name.
     */
    private static final String DEFAULT_JAR_NAME = "similarity-uniform-fuzzy-hash.jar";

    /**
     * Compute options.
     */
    private static final ArgsOptions[] COMPUTE_OPTIONS = {
            ArgsOptions.COMPUTE_FILE_HASH,
            ArgsOptions.COMPUTE_DIRECTORY_HASHES};

    /**
     * Save options.
     */
    private static final ArgsOptions[] SAVE_OPTIONS = {
            ArgsOptions.SAVE_TO_FILE};

    /**
     * Load options.
     */
    private static final ArgsOptions[] LOAD_OPTIONS = {
            ArgsOptions.LOAD_FROM_FILE};

    /**
     * Functional options.
     */
    private static final ArgsOptions[] FUNCTIONAL_OPTIONS = {
            ArgsOptions.REPRESENT_VISUALLY,
            ArgsOptions.COMPARE,
            ArgsOptions.COMPARE_VISUALLY,
            ArgsOptions.COMPARE_TO_ALL,
            ArgsOptions.COMPARE_ALL};

    /**
     * Enum of arguments options.
     */
    private enum ArgsOptions {

        /**
         * Help.
         */
        HELP(
                "help", "help", "",
                "Display help.",
                false, 0, -1),

        /**
         * Compute file hash.
         */
        COMPUTE_FILE_HASH(
                "cfh", "computeFileHash", "file",
                "Compute file hash.",
                false, 1, -1),

        /**
         * Compute directory hashes.
         */
        COMPUTE_DIRECTORY_HASHES(
                "cdh", "computeDirectoryHashes", "directory",
                "Compute directory hashes.",
                false, 1, -1),

        /**
         * Factor.
         */
        FACTOR(
                "f", "factor", "number",
                "Factor for hashes computation.",
                false, 1, 1),

        /**
         * Save to file.
         */
        SAVE_TO_FILE(
                "sf", "saveToFile", "file",
                "Save all computed hashes to file, appending them to its content.",
                false, 1, -1),

        /**
         * Load from file.
         */
        LOAD_FROM_FILE(
                "lf", "loadFromFile", "file",
                "Load saved hashes from file.",
                false, 1, -1),

        /**
         * Represent visually.
         */
        REPRESENT_VISUALLY(
                "rv", "representVisually", "name",
                "Represent visually a hash denoted by its name, "
                        + "or the computed file hash in case no argument is introduced.",
                false, 0, 1),

        /**
         * Compare.
         */
        COMPARE(
                "x", "compare", "name",
                "Compare two hashes denoted by their names, "
                        + "or the computed file hash to a hash denoted by its name "
                        + "in case one argument is introduced, "
                        + "or the two computed file hashes in case no argument is introduced.",
                false, 0, 2),

        /**
         * Compare visually.
         */
        COMPARE_VISUALLY(
                "xv", "compareVisually", "name",
                "Compare viually two hashes denoted by their names, "
                        + "or the computed file hash to a hash denoted by its name "
                        + "in case one argument is introduced, "
                        + "or the two computed file hashes in case no argument is introduced.",
                false, 0, 2),

        /**
         * To all.
         */
        COMPARE_TO_ALL(
                "xya", "compareToAll", "name",
                "Compare a hash denoted by its name, "
                        + "or the computed file hash in case no argument is introduced, "
                        + "to all computed and loaded hashes.",
                false, 0, 1),

        /**
         * Compare all.
         */
        COMPARE_ALL(
                "xa", "compareAll", "",
                "Compare all hashes denoted by their names, "
                        + "or all computed and loaded hashes in case no argument is introduced.",
                false, 0, -1),

        /**
         * Recursive.
         */
        RECURSIVE(
                "r", "recursive", "",
                "Traverse nested directories recursively.",
                false, 0, 0),

        /**
         * Overwrite.
         */
        OVERWRITE(
                "o", "overwrite", "",
                "Overwrite file contents when saving hashes to file instead of appending.",
                false, 0, 0),

        /**
         * Line wrap.
         */
        LINE_WRAP(
                "wrap", "lineWrap", "number",
                "Line wrap length for visual representations.",
                false, 1, 1),

        /**
         * Sorting by.
         */
        SORTING_BY(
                "sort", "sortingBy", "criteria",
                String.format(
                        "Sorting criteria for hash to all hashes comparisons.\r\n"
                                + "Possible values: %s.\r\n"
                                + "Default value: %s.",
                        SimilaritySortCriterias.valuesCsv(),
                        DEFAULT_SIMILARITY_SORT_CRITERIA),
                false, 0, 1),

        /**
         * Rows limit.
         */
        ROWS_LIMIT(
                "limit", "rowsLimit", "number",
                "Rows limit for hash to all hashes comparisons.",
                false, 1, 1),

        /**
         * Truncate names.
         */
        TRUNCATE_NAMES(
                "trunc", "truncateNames", "number",
                "Names maximum length for table prints.",
                false, 1, 1);

        /**
         * Short option.
         */
        private String shortOption;

        /**
         * Long option.
         */
        private String longOption;

        /**
         * Argument name (for display purposes).
         */
        private String argName;

        /**
         * Option description.
         */
        private String description;

        /**
         * Indicates if this option is required.
         */
        private boolean required;

        /**
         * Minimum number of arguments for this option.
         * A negative number indicates no limit.
         */
        private int minArgs;

        /**
         * Maximum number of arguments for this option.
         * A negative number indicates no limit.
         */
        private int maxArgs;

        /**
         * Constructor.
         * 
         * @param shortOption Short option.
         * @param longOption Long option.
         * @param argName Argument name (for display purposes).
         * @param description Option description.
         * @param required Indicates if this option is required.
         * @param minArgs Minimum number of arguments for this option.
         *        A negative number indicates no limit.
         * @param maxArgs Maximum number of arguments for this option.
         *        A negative number indicates no limit.
         */
        ArgsOptions(
                String shortOption,
                String longOption,
                String argName,
                String description,
                boolean required,
                int minArgs,
                int maxArgs) {

            this.shortOption = shortOption;
            this.longOption = longOption;
            this.argName = argName;
            this.description = description;
            this.required = required;
            this.minArgs = minArgs;
            this.maxArgs = maxArgs;

        }

        /**
         * @return The display String for this ArgsOption.
         */
        private String display() {

            return this.shortOption;

        }

        /**
         * @param argsOptions Array of ArgsOptions.
         * @return The comma separated values of display of an array of ArgsOptions.
         */
        private static String toDisplayCsv(
                ArgsOptions... argsOptions) {

            StringBuilder str = new StringBuilder();

            for (ArgsOptions argsOption : argsOptions) {
                if (str.length() != 0) {
                    str.append(", ");
                }
                str.append(argsOption.display());
            }

            return str.toString();

        }

    }

    /**
     * Private constructor.
     */
    private Main() {

    }

    /**
     * Main method.
     * 
     * @param args Run arguments.
     */
    public static void main(
            String[] args) {

        try {

            // Prepare and parse options.
            Options options = prepareOptions();
            Map<ArgsOptions, String[]> parsedOptions = parseOptions(options, args);

            // Display help.
            if (parsedOptions.containsKey(ArgsOptions.HELP) || parsedOptions.isEmpty()) {
                HelpFormatter helpFormatter = new HelpFormatter();
                helpFormatter.setOptionComparator(null);
                String cmdLineSyntax = "java -jar " + getJarName();
                helpFormatter.printHelp(cmdLineSyntax, options, true);
                return;
            }

            // Obtain values.
            String[] cfhArgs = parsedOptions.get(ArgsOptions.COMPUTE_FILE_HASH);
            String[] cdhArgs = parsedOptions.get(ArgsOptions.COMPUTE_DIRECTORY_HASHES);
            String[] fArgs = parsedOptions.get(ArgsOptions.FACTOR);
            String[] sfArgs = parsedOptions.get(ArgsOptions.SAVE_TO_FILE);
            String[] lfArgs = parsedOptions.get(ArgsOptions.LOAD_FROM_FILE);
            String[] rvArgs = parsedOptions.get(ArgsOptions.REPRESENT_VISUALLY);
            String[] xArgs = parsedOptions.get(ArgsOptions.COMPARE);
            String[] xvArgs = parsedOptions.get(ArgsOptions.COMPARE_VISUALLY);
            String[] xyaArgs = parsedOptions.get(ArgsOptions.COMPARE_TO_ALL);
            String[] xaArgs = parsedOptions.get(ArgsOptions.COMPARE_ALL);
            String[] rArgs = parsedOptions.get(ArgsOptions.RECURSIVE);
            String[] oArgs = parsedOptions.get(ArgsOptions.OVERWRITE);
            String[] wrapArgs = parsedOptions.get(ArgsOptions.LINE_WRAP);
            String[] sortArgs = parsedOptions.get(ArgsOptions.SORTING_BY);
            String[] limitArgs = parsedOptions.get(ArgsOptions.ROWS_LIMIT);
            String[] truncArgs = parsedOptions.get(ArgsOptions.TRUNCATE_NAMES);

            String rvArg = getOptionFirstArg(rvArgs);
            String xyaArg = getOptionFirstArg(xyaArgs);

            int factor = getOptionFirstArgInt(fArgs, 0, ArgsOptions.FACTOR);
            int lineWrap = getOptionFirstArgInt(wrapArgs, DEFAULT_LINE_WRAP, ArgsOptions.LINE_WRAP);
            int rowsLimit = getOptionFirstArgInt(limitArgs, -1, ArgsOptions.ROWS_LIMIT);
            int truncateNames = getOptionFirstArgInt(truncArgs, -1, ArgsOptions.TRUNCATE_NAMES);

            boolean recursive = rArgs != null;
            boolean overwrite = oArgs != null;

            SimilaritySortCriterias sortCriteria = null;
            String sortArg = getOptionFirstArg(sortArgs);
            if (sortArg != null) {
                if (sortArg.isEmpty()) {
                    sortCriteria = DEFAULT_SIMILARITY_SORT_CRITERIA;
                } else {
                    try {
                        sortCriteria = SimilaritySortCriterias.valueOf(
                                sortArg.toUpperCase());
                    } catch (IllegalArgumentException illegalArgumentException) {
                        throw new IllegalArgumentException(String.format(
                                "Invalid sorting criteria for option %s. Possible values: %s.",
                                ArgsOptions.SORTING_BY.display(),
                                SimilaritySortCriterias.valuesCsv()));
                    }
                }
            }

            // Logic checks.
            int nComputeOptions = countOptions(parsedOptions, COMPUTE_OPTIONS);
            int nSaveOptions = countOptions(parsedOptions, SAVE_OPTIONS);
            int nLoadOptions = countOptions(parsedOptions, LOAD_OPTIONS);
            int nFunctionalOptions = countOptions(parsedOptions, FUNCTIONAL_OPTIONS);

            if (nComputeOptions > 0 && fArgs == null) {
                throw new IllegalStateException(String.format(
                        "In order to use any of these options: %s, "
                                + "the option %s must be introduced.",
                        ArgsOptions.toDisplayCsv(COMPUTE_OPTIONS),
                        ArgsOptions.FACTOR.display()));
            }

            if (nSaveOptions > 0 && nComputeOptions == 0) {
                throw new IllegalStateException(String.format(
                        "In order to use the option %s, "
                                + "at least one of these options must be introduced: %s.",
                        ArgsOptions.toDisplayCsv(SAVE_OPTIONS),
                        ArgsOptions.toDisplayCsv(COMPUTE_OPTIONS)));
            }

            if (nFunctionalOptions > 0 && nComputeOptions == 0 && nLoadOptions == 0) {
                throw new IllegalStateException(String.format(
                        "In order to use any of these options: %s, "
                                + "at least one of these options must be introduced: %s, %s.",
                        ArgsOptions.toDisplayCsv(FUNCTIONAL_OPTIONS),
                        ArgsOptions.toDisplayCsv(COMPUTE_OPTIONS),
                        ArgsOptions.toDisplayCsv(LOAD_OPTIONS)));
            }

            if (nFunctionalOptions > 1) {
                throw new IllegalStateException(String.format(
                        "These options are mutually exclusive: %s.",
                        ArgsOptions.toDisplayCsv(FUNCTIONAL_OPTIONS)));
            }

            if (fArgs != null) {
                if (nComputeOptions == 0) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if "
                                    + "at least one  of these options is introduced: %s.",
                            ArgsOptions.FACTOR.display(),
                            ArgsOptions.toDisplayCsv(COMPUTE_OPTIONS)));
                }
            }

            if (rvArg != null) {
                if (rvArg.isEmpty() && !checkNArgs(cfhArgs, 1)) {
                    throw new IllegalStateException(String.format(
                            "Please, introduce an argument for the option %s, "
                                    + "or the option %s with one argument.",
                            ArgsOptions.REPRESENT_VISUALLY.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display()));
                }
            }

            if (xArgs != null) {
                if (xArgs.length == 0 && !checkNArgs(cfhArgs, 2)
                        || xArgs.length == 1 && !checkNArgs(cfhArgs, 1)) {
                    throw new IllegalStateException(String.format(
                            "Please, introduce two arguments for the option %s, "
                                    + "or one argument and the option %s with one argument, "
                                    + "or no arguments and the option %s with two arguments.",
                            ArgsOptions.COMPARE.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display()));
                }
            }

            if (xvArgs != null) {
                if (xvArgs.length == 0 && !checkNArgs(cfhArgs, 2)
                        || xvArgs.length == 1 && !checkNArgs(cfhArgs, 1)) {
                    throw new IllegalStateException(String.format(
                            "Please, introduce two arguments for the option %s, "
                                    + "or one argument and the option %s with one argument, "
                                    + "or no arguments and the option %s with two arguments.",
                            ArgsOptions.COMPARE_VISUALLY.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display()));
                }
            }

            if (xyaArg != null) {
                if (xyaArg.isEmpty() && !checkNArgs(cfhArgs, 1)) {
                    throw new IllegalStateException(String.format(
                            "Please, introduce an argument for the option %s, "
                                    + "or the option %s with one argument.",
                            ArgsOptions.COMPARE_ALL.display(),
                            ArgsOptions.COMPUTE_FILE_HASH.display()));
                }
            }

            if (rArgs != null) {
                if (cdhArgs == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if the option %s is introduced.",
                            ArgsOptions.RECURSIVE.display(),
                            ArgsOptions.COMPUTE_DIRECTORY_HASHES.display()));
                }
            }

            if (oArgs != null) {
                if (sfArgs == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if the option %s is introduced.",
                            ArgsOptions.OVERWRITE.display(),
                            ArgsOptions.SAVE_TO_FILE.display()));
                }
            }

            if (wrapArgs != null) {
                if (rvArg == null && xvArgs == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if "
                                    + "at least one of these options is introduced: %s.",
                            ArgsOptions.LINE_WRAP.display(),
                            ArgsOptions.toDisplayCsv(
                                    ArgsOptions.REPRESENT_VISUALLY,
                                    ArgsOptions.COMPARE_VISUALLY)));
                }
            }

            if (sortArg != null) {
                if (xyaArg == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if the option %s is introduced.",
                            ArgsOptions.SORTING_BY.display(),
                            ArgsOptions.COMPARE_TO_ALL.display()));
                }
            }

            if (limitArgs != null) {
                if (xyaArg == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if the option %s is introduced.",
                            ArgsOptions.ROWS_LIMIT.display(),
                            ArgsOptions.COMPARE_TO_ALL.display()));
                }
            }

            if (truncArgs != null) {
                if (xyaArg == null && xaArgs == null) {
                    throw new IllegalStateException(String.format(
                            "The option %s is only valid if "
                                    + "at least one of these options is introduced: %s.",
                            ArgsOptions.TRUNCATE_NAMES.display(),
                            ArgsOptions.toDisplayCsv(
                                    ArgsOptions.COMPARE_TO_ALL,
                                    ArgsOptions.COMPARE_ALL)));
                }
            }

            // Execution.
            File file = null;
            File directory = null;
            String name = null;
            UniformFuzzyHash hash = null;
            Map<String, UniformFuzzyHash> hashes = null;

            String computedFileHashName1 = null;
            String computedFileHashName2 = null;
            UniformFuzzyHash computedFileHash1 = null;
            UniformFuzzyHash computedFileHash2 = null;

            Map<String, UniformFuzzyHash> computedHashes = new LinkedHashMap<>();
            Map<String, UniformFuzzyHash> loadedHashes = new LinkedHashMap<>();
            Map<String, UniformFuzzyHash> computedAndLoadedHashes = new LinkedHashMap<>();

            String compareHashName1 = null;
            String compareHashName2 = null;
            UniformFuzzyHash compareHash1 = null;
            UniformFuzzyHash compareHash2 = null;

            if (cfhArgs != null) {
                for (String computeFileHashArg : cfhArgs) {
                    file = new File(computeFileHashArg);
                    name = file.getName();
                    hash = new UniformFuzzyHash(file, factor);
                    if (computedFileHash1 == null) {
                        computedFileHashName1 = name;
                        computedFileHash1 = hash;
                    } else if (computedFileHash2 == null) {
                        computedFileHashName2 = name;
                        computedFileHash2 = hash;
                    }
                    computedHashes.put(name, hash);
                    computedAndLoadedHashes.put(name, hash);
                }
            }

            if (cdhArgs != null) {
                for (String computeDirectoryHashesArg : cdhArgs) {
                    directory = new File(computeDirectoryHashesArg);
                    hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                            directory, factor, recursive);
                    computedHashes.putAll(hashes);
                    computedAndLoadedHashes.putAll(hashes);
                }
            }

            if (sfArgs != null) {
                for (String saveToFileArg : sfArgs) {
                    file = new File(saveToFileArg);
                    UniformFuzzyHashes.saveToFile(computedHashes, file, !overwrite);
                }
            }

            if (lfArgs != null) {
                for (String loadFromFileArg : lfArgs) {
                    file = new File(loadFromFileArg);
                    hashes = UniformFuzzyHashes.loadFromFile(file);
                    loadedHashes.putAll(hashes);
                    computedAndLoadedHashes.putAll(hashes);
                }
            }

            if (nSaveOptions == 0 && nFunctionalOptions == 0) {
                if (!computedHashes.isEmpty() && !loadedHashes.isEmpty()) {
                    System.out.println();
                    System.out.println(IGNORE_MARK + " Computed Hashes:");
                    UniformFuzzyHashes.printHashes(computedHashes, true);
                    System.out.println(IGNORE_MARK + " Loaded Hashes:");
                    UniformFuzzyHashes.printHashes(loadedHashes, true);
                } else if (!computedHashes.isEmpty()) {
                    UniformFuzzyHashes.printHashes(computedHashes, true);
                } else if (!loadedHashes.isEmpty()) {
                    UniformFuzzyHashes.printHashes(loadedHashes, true);
                }
            }

            if (rvArg != null) {
                if (rvArg.isEmpty()) {
                    name = computedFileHashName1;
                    hash = computedFileHash1;
                } else {
                    name = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, rvArg);
                    hash = computedAndLoadedHashes.get(name);
                }
                VisualRepresentation.print(hash,
                        DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR, lineWrap, true);
            }

            if (xArgs != null) {
                if (xArgs.length == 0) {
                    compareHashName1 = computedFileHashName1;
                    compareHash1 = computedFileHash1;
                    compareHashName2 = computedFileHashName2;
                    compareHash2 = computedFileHash2;
                } else if (xArgs.length == 1) {
                    compareHashName1 = computedFileHashName1;
                    compareHash1 = computedFileHash1;
                    compareHashName2 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xArgs[0]);
                    compareHash2 = computedAndLoadedHashes.get(compareHashName2);
                } else if (xArgs.length == 2) {
                    compareHashName1 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xArgs[0]);
                    compareHash1 = computedAndLoadedHashes.get(compareHashName1);
                    compareHashName2 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xArgs[1]);
                    compareHash2 = computedAndLoadedHashes.get(compareHashName2);
                }
                System.out.println(DECIMALS_FORMAT.format(compareHash1.similarity(compareHash2)));
            }

            if (xvArgs != null) {
                if (xvArgs.length == 0) {
                    compareHashName1 = computedFileHashName1;
                    compareHash1 = computedFileHash1;
                    compareHashName2 = computedFileHashName2;
                    compareHash2 = computedFileHash2;
                } else if (xvArgs.length == 1) {
                    compareHashName1 = computedFileHashName1;
                    compareHash1 = computedFileHash1;
                    compareHashName2 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xvArgs[0]);
                    compareHash2 = computedAndLoadedHashes.get(compareHashName2);
                } else if (xvArgs.length == 2) {
                    compareHashName1 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xvArgs[0]);
                    compareHash1 = computedAndLoadedHashes.get(compareHashName1);
                    compareHashName2 = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xvArgs[1]);
                    compareHash2 = computedAndLoadedHashes.get(compareHashName2);
                }
                VisualRepresentation.printCompared(compareHash1, compareHash2,
                        DEFAULT_BASE, DEFAULT_FACTOR_DIVISOR, lineWrap, true);
                System.out.println(" Similarity: "
                        + DECIMALS_FORMAT.format(compareHash1.similarity(compareHash2)));
                System.out.println();
            }

            if (xyaArg != null) {
                if (xyaArg.isEmpty()) {
                    name = computedFileHashName1;
                    hash = computedFileHash1;
                } else {
                    name = getComputedOrLoadedHashName(
                            computedAndLoadedHashes, xyaArg);
                    hash = computedAndLoadedHashes.get(name);
                }
                UniformFuzzyHashes.printSimilarities(name, hash, computedAndLoadedHashes,
                        sortCriteria, rowsLimit, truncateNames);
            }

            if (xaArgs != null) {
                if (xaArgs.length == 0) {
                    hashes = computedAndLoadedHashes;
                } else {
                    hashes = new LinkedHashMap<>();
                    for (String xaArg : xaArgs) {
                        name = getComputedOrLoadedHashName(
                                computedAndLoadedHashes, xaArg);
                        hash = computedAndLoadedHashes.get(name);
                        hashes.put(name, hash);
                    }
                }
                UniformFuzzyHashes.printSimilarityTable(hashes,
                        truncateNames);
            }

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            System.out.println(String.format(
                    "Run with the argument %s or with no arguments to display help.",
                    ArgsOptions.HELP.display()));
            System.exit(1);
        }

    }

    /**
     * Prepares the options from the ArgsOptions enum.
     * 
     * @return The prepared options.
     */
    private static Options prepareOptions() {

        Options options = new Options();

        for (ArgsOptions argOption : ArgsOptions.values()) {
            options.addOption(Option
                    .builder(argOption.display())
                    .longOpt(argOption.longOption)
                    .argName(argOption.argName)
                    .desc(argOption.description)
                    .required(argOption.required)
                    .hasArgs()
                    .optionalArg(true)
                    .build());
        }

        return options;

    }

    /**
     * Parses the introduced arguments to a map from ArgsOptions to String[] of introduced values.
     * 
     * @param options Prepared options.
     * @param args Introduced arguments.
     * @return Map from ArgsOptions to String[] of introduced values.
     * @throws ParseException If an error occurs parsing any of the options or the introduced
     *         arguments do not fit any of them.
     */
    private static Map<ArgsOptions, String[]> parseOptions(
            Options options,
            String[] args)
            throws ParseException {

        CommandLine cmd = new DefaultParser().parse(options, args);
        Map<ArgsOptions, String[]> parsedOptions = new HashMap<>(ArgsOptions.values().length);

        for (ArgsOptions argsOption : ArgsOptions.values()) {

            if (cmd.hasOption(argsOption.longOption)) {

                String[] optionValues = cmd.getOptionValues(argsOption.longOption);
                if (optionValues == null) {
                    optionValues = new String[0];
                }

                if (argsOption.minArgs > 0 && optionValues.length == 0) {
                    throw new ParseException(String.format(
                            "Missing %s for option: %s.",
                            argsOption.maxArgs < 0 || argsOption.maxArgs > 1
                                    ? "arguments" : "argument",
                            argsOption.display()));
                }

                if (argsOption.maxArgs == 0 && optionValues.length > 0) {
                    throw new ParseException(String.format(
                            "Option %s takes no arguments.",
                            argsOption.display()));
                }

                if (argsOption.minArgs > 0 && optionValues.length < argsOption.minArgs) {
                    throw new ParseException(String.format(
                            "Too few arguments for option: %s.",
                            argsOption.display()));
                }

                if (argsOption.maxArgs > 0 && optionValues.length > argsOption.maxArgs) {
                    throw new ParseException(String.format(
                            "Too many arguments for option: %s.",
                            argsOption.display()));
                }

                parsedOptions.put(argsOption, optionValues);

            } else {

                if (argsOption.required) {
                    throw new ParseException(String.format(
                            "Missing required option: %s.",
                            argsOption.display()));
                }

            }

        }

        return parsedOptions;

    }

    /**
     * Gets the first introduced argument of an option.
     * 
     * @param optionArgs The option introduced arguments.
     * @return The option first introduced argument.
     *         If the option was not introduced, null is returned.
     *         If the option was introduced with no argument, "" is returned.
     */
    private static String getOptionFirstArg(
            String[] optionArgs) {

        if (optionArgs == null) {
            return null;
        }

        if (optionArgs.length == 0) {
            return "";
        }

        return optionArgs[0];

    }

    /**
     * Gets the first introduced argument of an option parsed to int.
     * 
     * @param optionArgs The option introduced arguments.
     * @param emptyValue Value which is returned if the option was not introduced, or was introduced
     *        with no argument.
     * @param argsOption The option.
     * @return The option first introduced argument parsed to int.
     *         If the option was not introduced, or was introduced with no argument, emptyValue is
     *         returned.
     * @throws ParseException If an error occurs parsing the argument to int.
     */
    private static int getOptionFirstArgInt(
            String[] optionArgs,
            int emptyValue,
            ArgsOptions argsOption)
            throws ParseException {

        String optionArg = getOptionFirstArg(optionArgs);

        if (optionArg == null || optionArg.isEmpty()) {
            return emptyValue;
        }

        try {
            return Integer.parseInt(optionArg);
        } catch (NumberFormatException numberFormatException) {
            throw new ParseException(String.format(
                    "Option %s must be numeric.",
                    argsOption.display()));
        }

    }

    /**
     * @param parsedOptions Map from ArgsOptions to String[] of parsed options.
     * @param argsOptions Array of ArgsOptions.
     * @return The number of argsOptions present in parsedOptions.
     */
    private static int countOptions(
            Map<ArgsOptions, String[]> parsedOptions,
            ArgsOptions... argsOptions) {

        int count = 0;

        for (ArgsOptions argsOption : argsOptions) {
            if (parsedOptions.get(argsOption) != null) {
                count++;
            }
        }

        return count;

    }

    /**
     * Checks that an option was introduced with a number of arguments.
     * 
     * @param optionArgs Option arguments.
     * @param nArgs Number of arguments to check (introduce a negative number to check that the
     *        option was not introduced).
     * @return True if the option was introduced with that number of arguments. False otherwise.
     */
    private static boolean checkNArgs(
            String[] optionArgs,
            int nArgs) {

        if (nArgs < 0) {
            return optionArgs == null;
        } else {
            return optionArgs != null && optionArgs.length == nArgs;
        }

    }

    /**
     * @param computedAndLoadedHashes Map of computed and loaded hashes.
     * @param nameOrPath Hash name or file path denoting a computed or loaded Uniform Fuzzy Hash.
     * @return The map key to the Uniform Fuzzy Hash denoted by nameOrPath.
     * @throws IllegalStateException if the hash has not been computed or loaded.
     */
    private static String getComputedOrLoadedHashName(
            Map<String, UniformFuzzyHash> computedAndLoadedHashes,
            String nameOrPath) {

        UniformFuzzyHash hash = computedAndLoadedHashes.get(nameOrPath);

        if (hash == null) {
            File file = new File(nameOrPath);
            if (file.exists() && file.isFile()) {
                nameOrPath = file.getName();
                hash = computedAndLoadedHashes.get(nameOrPath);
            }
        }

        if (hash == null) {
            throw new IllegalStateException(String.format(
                    "Hash %s has not been computed or loaded.",
                    nameOrPath));
        }

        return nameOrPath;

    }

    /**
     * @return The current jar name.
     */
    private static String getJarName() {

        try {
            String path = Main.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            return new File(path).getName();
        } catch (Exception exception) {
            return DEFAULT_JAR_NAME;
        }

    }

}
