package securitybug.similarityuniformfuzzyhash;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static securitybug.similarityuniformfuzzyhash.ToStringUtils.NAME_SEPARATOR;

import securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.SimilaritySortCriterias;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.util.Arrays;
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
     * Application name.
     */
    private static final String APP_NAME = "similarity-uniform-fuzzy-hash.jar";

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

        Options options = new Options();
        Option option = null;

        // factor.
        option = new Option(
                "f",
                "factor",
                true,
                "Factor.");
        option.setRequired(false);
        options.addOption(option);

        // computeFileHash.
        option = new Option(
                "cfh",
                "computeFileHash",
                true,
                "Compute file hash.");
        option.setRequired(false);
        options.addOption(option);

        // computeDirectoryHashes.
        option = new Option(
                "cdh",
                "computeDirectoryHashes",
                true,
                "Compute directory hashes.");
        option.setRequired(false);
        options.addOption(option);

        // recursive.
        option = new Option(
                "r",
                "R",
                false,
                "Traverse nested directories recursively.");
        option.setRequired(false);
        options.addOption(option);

        // saveToFileOverwriting.
        option = new Option(
                "sfo",
                "saveToFileOverwriting",
                true,
                "Save computed hashes to file overwriting its content.");
        option.setRequired(false);
        options.addOption(option);

        // saveToFileAppending.
        option = new Option(
                "sfa",
                "saveToFileAppending",
                true,
                "Save computed hashes to file appending them to its content.");
        option.setRequired(false);
        options.addOption(option);

        // representFileVisually.
        option = new Option(
                "rfv",
                "representFileVisually",
                true,
                "Represent file visually.");
        option.setRequired(false);
        options.addOption(option);

        // lineWrap.
        option = new Option(
                "wrap",
                "lineWrap",
                true,
                "Line wrap length for visual representations.");
        option.setRequired(false);
        options.addOption(option);

        // compareFile.
        option = new Option(
                "xf",
                "compareFile",
                true,
                "Compare file...");
        option.setRequired(false);
        options.addOption(option);

        // toFile.
        option = new Option(
                "yf",
                "toFile",
                true,
                "...to file.");
        option.setRequired(false);
        options.addOption(option);

        // toFileVisually.
        option = new Option(
                "yfv",
                "toFileVisually",
                true,
                "...to file visually.");
        option.setRequired(false);
        options.addOption(option);

        // toSavedHashes.
        option = new Option(
                "ysh",
                "toSavedHashes",
                true,
                "...to saved hashes.");
        option.setRequired(false);
        options.addOption(option);

        // toDirectory.
        option = new Option(
                "yd",
                "toDirectory",
                true,
                "...to directory.");
        option.setRequired(false);
        options.addOption(option);

        // sorting.
        option = new Option(
                "sort",
                "sorting",
                true,
                "Sorting criteria for comparisons. Possible values: "
                        + Arrays.asList(SimilaritySortCriterias.values()));
        option.setRequired(false);
        options.addOption(option);

        // compareSavedHashes.
        option = new Option(
                "xsh",
                "compareSavedHashes",
                true,
                "Compare saved hashes between themselves.");
        option.setRequired(false);
        options.addOption(option);

        // compareDirectory.
        option = new Option(
                "xd",
                "compareDirectory",
                true,
                "Compare directory files between themselves.");
        option.setRequired(false);
        options.addOption(option);

        // truncateNamesLength.
        option = new Option(
                "trunc",
                "truncateNamesLength",
                true,
                "Truncate names length.");
        option.setRequired(false);
        options.addOption(option);

        // Parse arguments.
        CommandLine cmd = null;
        HelpFormatter helpFormatter = new HelpFormatter();
        try {
            cmd = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            helpFormatter.printHelp(APP_NAME, options);
            System.exit(1);
            return;
        }

        if (cmd.getOptions().length == 0) {
            helpFormatter.printHelp(APP_NAME, options);
        }

        // Obtain values.
        String factorArg =
                cmd.getOptionValue("factor");

        String computeFileHashArg =
                cmd.getOptionValue("computeFileHash");

        String computeDirectoryHashesArg =
                cmd.getOptionValue("computeDirectoryHashes");

        boolean recursiveArg =
                cmd.hasOption("R");

        String saveToFileOverwritingArg =
                cmd.getOptionValue("saveToFileOverwriting");

        String saveToFileAppendingArg =
                cmd.getOptionValue("saveToFileAppending");

        String representFileVisuallyArg =
                cmd.getOptionValue("representFileVisually");

        String lineWrapArg =
                cmd.getOptionValue("lineWrap");

        String compareFileArg =
                cmd.getOptionValue("compareFile");

        String toFileArg =
                cmd.getOptionValue("toFile");

        String toFileVisuallyArg =
                cmd.getOptionValue("toFileVisually");

        String toSavedHashesArg =
                cmd.getOptionValue("toSavedHashes");

        String toDirectoryArg =
                cmd.getOptionValue("toDirectory");

        String sortingArg =
                cmd.getOptionValue("sorting");

        String compareSavedHashesArg =
                cmd.getOptionValue("compareSavedHashes");

        String compareDirectoryArg =
                cmd.getOptionValue("compareDirectory");

        String truncateNamesLengthArg =
                cmd.getOptionValue("truncateNamesLength");

        // Execute commands.
        try {

            // Logic checks.
            boolean computeArg = isNotBlank(computeFileHashArg)
                    || isNotBlank(computeDirectoryHashesArg);

            boolean saveArg = isNotBlank(saveToFileOverwritingArg)
                    || isNotBlank(saveToFileAppendingArg);

            boolean compareFromArg = isNotBlank(compareFileArg);

            boolean compareToArg = isNotBlank(toFileArg)
                    || isNotBlank(toFileVisuallyArg)
                    || isNotBlank(toSavedHashesArg)
                    || isNotBlank(toDirectoryArg);

            boolean factorRequired = computeArg
                    || isNotBlank(representFileVisuallyArg)
                    || isNotBlank(compareFileArg)
                    || isNotBlank(compareDirectoryArg);

            boolean possibleRecursive = isNotBlank(computeDirectoryHashesArg)
                    || isNotBlank(toDirectoryArg)
                    || isNotBlank(compareDirectoryArg);

            boolean possibleTrunc = isNotBlank(toSavedHashesArg)
                    || isNotBlank(toDirectoryArg)
                    || isNotBlank(compareSavedHashesArg)
                    || isNotBlank(compareDirectoryArg);

            boolean possibleSort = isNotBlank(toSavedHashesArg)
                    || isNotBlank(toDirectoryArg);

            boolean possibleWrap = isNotBlank(representFileVisuallyArg)
                    || isNotBlank(toFileVisuallyArg);

            if (saveArg && !computeArg) {
                throw new IllegalStateException("Please, introduce a file or a directory"
                        + " to compute its hash or hashes before saving them.");
            }

            if (compareFromArg && !compareToArg) {
                throw new IllegalStateException("Please, introduce a file, directory,"
                        + " or file of saved hashes to compare to.");
            }

            if (compareToArg && !compareFromArg) {
                throw new IllegalStateException("Please, introduce a file to compare.");
            }

            int factor = 0;
            if (factorRequired) {
                if (isBlank(factorArg)) {
                    throw new IllegalStateException("Please, introduce a factor.");
                }
                try {
                    factor = Integer.parseInt(factorArg);
                } catch (NumberFormatException numberFormatException) {
                    throw new IllegalArgumentException("Factor must be a number.");
                }
            }

            boolean recursive = false;
            if (recursiveArg) {
                if (!possibleRecursive) {
                    throw new IllegalStateException("Recursive option "
                            + "is only valid for directory commands.");
                }
                recursive = true;
            }

            int truncateNamesLength = 0;
            if (isNotBlank(truncateNamesLengthArg)) {
                if (!possibleTrunc) {
                    throw new IllegalStateException("Truncate names length option "
                            + "is only valid for table printing commands.");
                }
                try {
                    truncateNamesLength = Integer.parseInt(truncateNamesLengthArg);
                } catch (NumberFormatException numberFormatException) {
                    throw new IllegalArgumentException("Truncate names length must be a number.");
                }
            }

            SimilaritySortCriterias sortCriteria = null;
            if (isNotBlank(sortingArg)) {
                if (!possibleSort) {
                    throw new IllegalStateException("Sorting option "
                            + "is only valid for file to files or hashes comparison.");
                }
                try {
                    sortCriteria = SimilaritySortCriterias.valueOf(sortingArg);
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new IllegalArgumentException("Invalid sorting value. Possible values: "
                            + Arrays.asList(SimilaritySortCriterias.values()));
                }
            }

            int lineWrap = VisualRepresentation.DEFAULT_LINE_WRAP;
            if (isNotBlank(lineWrapArg)) {
                if (!possibleWrap) {
                    throw new IllegalStateException("Line wrap option "
                            + "is only valid for visual representations and comparisons.");
                }
                try {
                    lineWrap = Integer.parseInt(lineWrapArg);
                } catch (NumberFormatException numberFormatException) {
                    throw new IllegalArgumentException("Line wrap length must be a number.");
                }
            }

            File file = null;
            File directory = null;
            UniformFuzzyHash hash = null;
            Map<String, UniformFuzzyHash> hashes = null;

            Map<String, UniformFuzzyHash> computedHashes =
                    new LinkedHashMap<String, UniformFuzzyHash>();
            File compareFile = null;
            UniformFuzzyHash compareHash = null;

            // Compute file hash.
            if (isNotBlank(computeFileHashArg)) {

                file = new File(computeFileHashArg);
                hash = new UniformFuzzyHash(file, factor);
                computedHashes.put(file.getName(), hash);

                if (!saveArg) {
                    System.out.println(file.getName() + NAME_SEPARATOR + hash);
                }

            }

            // Compute directory files hashes.
            if (isNotBlank(computeDirectoryHashesArg)) {

                directory = new File(computeDirectoryHashesArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, recursive);
                computedHashes.putAll(hashes);

                if (!saveArg) {
                    for (String name : hashes.keySet()) {
                        System.out.println(name + NAME_SEPARATOR + hashes.get(name));
                    }
                }

            }

            // Save to file overwriting.
            if (isNotBlank(saveToFileOverwritingArg)) {

                file = new File(saveToFileOverwritingArg);
                UniformFuzzyHashes.saveToFile(computedHashes, file, false);

            }

            // Save to file appending.
            if (isNotBlank(saveToFileAppendingArg)) {

                file = new File(saveToFileAppendingArg);
                UniformFuzzyHashes.saveToFile(computedHashes, file, true);

            }

            // Represent file visually.
            if (isNotBlank(representFileVisuallyArg)) {

                file = new File(representFileVisuallyArg);
                hash = new UniformFuzzyHash(file, factor);

                VisualRepresentation.print(
                        hash,
                        VisualRepresentation.DEFAULT_BASE,
                        VisualRepresentation.DEFAULT_FACTOR_DIVISOR,
                        lineWrap,
                        true);

            }

            // Compare file.
            if (isNotBlank(compareFileArg)) {

                compareFile = new File(compareFileArg);
                compareHash = new UniformFuzzyHash(compareFile, factor);

            }

            // To file.
            if (isNotBlank(toFileArg)) {

                file = new File(toFileArg);
                hash = new UniformFuzzyHash(file, factor);

                System.out.println(compareHash.similarity(hash));

            }

            // To file visually.
            if (isNotBlank(toFileVisuallyArg)) {

                file = new File(toFileVisuallyArg);
                hash = new UniformFuzzyHash(file, factor);

                VisualRepresentation.printCompared(
                        compareHash,
                        hash,
                        VisualRepresentation.DEFAULT_BASE,
                        VisualRepresentation.DEFAULT_FACTOR_DIVISOR,
                        lineWrap,
                        true);

                System.out.println(compareHash.similarity(hash));

            }

            // To saved hashes.
            if (isNotBlank(toSavedHashesArg)) {

                file = new File(toSavedHashesArg);
                hashes = UniformFuzzyHashes.loadFromFile(file);

                UniformFuzzyHashes.printSimilarities(
                        compareFile.getName(),
                        compareHash,
                        hashes,
                        sortCriteria,
                        truncateNamesLength);

            }

            // To directory files.
            if (isNotBlank(toDirectoryArg)) {

                directory = new File(toDirectoryArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, recursive);

                UniformFuzzyHashes.printSimilarities(
                        compareFile.getName(),
                        compareHash,
                        hashes,
                        sortCriteria,
                        truncateNamesLength);

            }

            // Compare saved hashes.
            if (isNotBlank(compareSavedHashesArg)) {

                file = new File(compareSavedHashesArg);
                hashes = UniformFuzzyHashes.loadFromFile(file);

                UniformFuzzyHashes.printSimilarityTable(hashes, truncateNamesLength);

            }

            // Compare directory files.
            if (isNotBlank(compareDirectoryArg)) {

                directory = new File(compareDirectoryArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, recursive);

                UniformFuzzyHashes.printSimilarityTable(hashes, truncateNamesLength);

            }

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            System.exit(1);
            return;
        }

    }

}
