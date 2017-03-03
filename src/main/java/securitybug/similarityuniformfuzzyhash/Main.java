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
                "cf",
                "computeFileHash",
                true,
                "Compute hash over a file.");
        option.setRequired(false);
        options.addOption(option);

        // computeDirectoryFilesHashes.
        option = new Option(
                "cd",
                "computeDirectoryFilesHashes",
                true,
                "Compute hashes over the files of a directory.");
        option.setRequired(false);
        options.addOption(option);

        // computeDirectoryFilesHashesNested.
        option = new Option(
                "cdn",
                "computeDirectoryFilesHashesNested",
                true,
                "Compute hashes over the files of a nested directory.");
        option.setRequired(false);
        options.addOption(option);

        // saveToFileOverwriting.
        option = new Option(
                "so",
                "saveToFileOverwriting",
                true,
                "Save computed hashes to file overwriting its content.");
        option.setRequired(false);
        options.addOption(option);

        // saveToFileAppending.
        option = new Option(
                "sa",
                "saveToFileAppending",
                true,
                "Save computed hashes to file appending them to its content.");
        option.setRequired(false);
        options.addOption(option);

        // representFileVisually
        option = new Option(
                "fv",
                "representFileVisually",
                true,
                "Represent file visually.");
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
                "ys",
                "toSavedHashes",
                true,
                "...to saved hashes.");
        option.setRequired(false);
        options.addOption(option);

        // toDirectoryFiles.
        option = new Option(
                "yd",
                "toDirectoryFiles",
                true,
                "...to directory files.");
        option.setRequired(false);
        options.addOption(option);

        // toDirectoryFilesNested.
        option = new Option(
                "ydn",
                "toDirectoryFilesNested",
                true,
                "...to nested directory files.");
        option.setRequired(false);
        options.addOption(option);

        // sorting.
        option = new Option(
                "sort",
                "sorting",
                true,
                "Sorting criteria for comparisons. "
                        + "HASH_TO_HASHES_ASC "
                        + "HASH_TO_HASHES_DESC "
                        + "HASHES_TO_HASH_ASC "
                        + "HASHES_TO_HASH_DESC ");
        option.setRequired(false);
        options.addOption(option);

        // compareSavedHashes.
        option = new Option(
                "xs",
                "compareSavedHashes",
                true,
                "Compare saved hashes between themselves.");
        option.setRequired(false);
        options.addOption(option);

        // compareDirectoryFiles.
        option = new Option(
                "xd",
                "compareDirectoryFiles",
                true,
                "Compare directory files between themselves.");
        option.setRequired(false);
        options.addOption(option);

        // compareDirectoryFilesNested.
        option = new Option(
                "xdn",
                "compareDirectoryFilesNested",
                true,
                "Compare nested directory files between themselves.");
        option.setRequired(false);
        options.addOption(option);

        // Parse arguments.
        CommandLine cmd = null;
        try {
            cmd = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            new HelpFormatter().printHelp(APP_NAME, options);
            System.exit(1);
            return;
        }

        // Obtain values.
        String factorArg =
                cmd.getOptionValue("factor");

        String computeFileHashArg =
                cmd.getOptionValue("computeFileHash");

        String computeDirectoryFilesHashesArg =
                cmd.getOptionValue("computeDirectoryFilesHashes");

        String computeDirectoryFilesHashesNestedArg =
                cmd.getOptionValue("computeDirectoryFilesHashesNested");

        String saveToFileOverwritingArg =
                cmd.getOptionValue("saveToFileOverwriting");

        String saveToFileAppendingArg =
                cmd.getOptionValue("saveToFileAppending");

        String representFileVisuallyArg =
                cmd.getOptionValue("representFileVisually");

        String compareFileArg =
                cmd.getOptionValue("compareFile");

        String toFileArg =
                cmd.getOptionValue("toFile");

        String toFileVisuallyArg =
                cmd.getOptionValue("toFileVisually");

        String toSavedHashesArg =
                cmd.getOptionValue("toSavedHashes");

        String toDirectoryFilesArg =
                cmd.getOptionValue("toDirectoryFiles");

        String toDirectoryFilesNestedArg =
                cmd.getOptionValue("toDirectoryFilesNested");

        String sortingArg =
                cmd.getOptionValue("sorting");

        String compareSavedHashesArg =
                cmd.getOptionValue("compareSavedHashes");

        String compareDirectoryFilesArg =
                cmd.getOptionValue("compareDirectoryFiles");

        String compareDirectoryFilesNestedArg =
                cmd.getOptionValue("compareDirectoryFilesNested");

        // Execute commands.
        try {

            // Logic checks.
            boolean computeArg = isNotBlank(computeFileHashArg)
                    || isNotBlank(computeDirectoryFilesHashesArg)
                    || isNotBlank(computeDirectoryFilesHashesNestedArg);

            boolean saveArg = isNotBlank(saveToFileOverwritingArg)
                    || isNotBlank(saveToFileAppendingArg);

            boolean compareFromArg = isNotBlank(compareFileArg);

            boolean compareToArg = isNotBlank(toFileArg)
                    || isNotBlank(toFileVisuallyArg)
                    || isNotBlank(toSavedHashesArg)
                    || isNotBlank(toDirectoryFilesArg)
                    || isNotBlank(toDirectoryFilesNestedArg);

            boolean factorRequired = computeArg
                    || isNotBlank(representFileVisuallyArg)
                    || isNotBlank(compareFileArg)
                    || isNotBlank(compareDirectoryFilesArg)
                    || isNotBlank(compareDirectoryFilesNestedArg);

            if (saveArg && !computeArg) {
                throw new IllegalStateException(
                        "Please, introduce a file or a directory to compute its hash or hashes.");
            }

            if (compareFromArg && !compareToArg) {
                throw new IllegalStateException("Please, introduce a file, directory,"
                        + " or file of saved hashes to compare to.");
            }

            if (compareToArg && !compareFromArg) {
                throw new IllegalStateException("Please, introduce a file to compare.");
            }

            int factor = 0;
            File file = null;
            File directory = null;
            UniformFuzzyHash hash = null;
            Map<String, UniformFuzzyHash> hashes = null;

            Map<String, UniformFuzzyHash> computedHashes =
                    new LinkedHashMap<String, UniformFuzzyHash>();
            File compareFile = null;
            UniformFuzzyHash compareHash = null;

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
            if (isNotBlank(computeDirectoryFilesHashesArg)) {

                directory = new File(computeDirectoryFilesHashesArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, false);
                computedHashes.putAll(hashes);

                if (!saveArg) {
                    for (String name : hashes.keySet()) {
                        System.out.println(name + NAME_SEPARATOR + hashes.get(name));
                    }
                }

            }

            // Compute directory files hashes nested.
            if (isNotBlank(computeDirectoryFilesHashesNestedArg)) {

                directory = new File(computeDirectoryFilesHashesNestedArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, true);
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

                VisualRepresentation.print(hash);

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

                VisualRepresentation.printCompared(compareHash, hash);

                System.out.println(compareHash.similarity(hash));

            }

            // To saved hashes.
            if (isNotBlank(toSavedHashesArg)) {

                file = new File(toSavedHashesArg);
                hashes = UniformFuzzyHashes.loadFromFile(file);

                UniformFuzzyHashes.printSimilarities(compareFile.getName(), compareHash, hashes,
                        isBlank(sortingArg) ? null : SimilaritySortCriterias.valueOf(sortingArg));

            }

            // To directory files.
            if (isNotBlank(toDirectoryFilesArg)) {

                directory = new File(toDirectoryFilesArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, false);

                UniformFuzzyHashes.printSimilarities(compareFile.getName(), compareHash, hashes,
                        isBlank(sortingArg) ? null : SimilaritySortCriterias.valueOf(sortingArg));

            }

            // To directory files nested.
            if (isNotBlank(toDirectoryFilesNestedArg)) {

                directory = new File(toDirectoryFilesNestedArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, true);

                UniformFuzzyHashes.printSimilarities(compareFile.getName(), compareHash, hashes,
                        isBlank(sortingArg) ? null : SimilaritySortCriterias.valueOf(sortingArg));

            }

            // Compare saved hashes.
            if (isNotBlank(compareSavedHashesArg)) {

                file = new File(compareSavedHashesArg);
                hashes = UniformFuzzyHashes.loadFromFile(file);

                UniformFuzzyHashes.printSimilarityTable(hashes);

            }

            // Compare directory files.
            if (isNotBlank(compareDirectoryFilesArg)) {

                directory = new File(compareDirectoryFilesArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, false);

                UniformFuzzyHashes.printSimilarityTable(hashes);

            }

            // Compare directory files nested.
            if (isNotBlank(compareDirectoryFilesNestedArg)) {

                directory = new File(compareDirectoryFilesNestedArg);
                hashes = UniformFuzzyHashes.computeNamedHashesFromDirectoryFiles(
                        directory, factor, true);

                UniformFuzzyHashes.printSimilarityTable(hashes);

            }

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            System.exit(1);
        }

    }

}
