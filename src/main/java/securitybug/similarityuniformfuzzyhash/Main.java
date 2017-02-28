package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.NAME_SEPARATOR;

import securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.SimilaritySortCriterias;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;

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
    public static void main(String[] args) {

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

        try {

            Map<String, UniformFuzzyHash> namesToHashes =
                    new LinkedHashMap<String, UniformFuzzyHash>();

            // Compute hashes.
            if (!StringUtils.isEmpty(computeFileHashArg)) {

                int factor = checkFactorArg(factorArg);
                File file = new File(computeFileHashArg);
                UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
                namesToHashes.put(file.getName(), hash);

                if (StringUtils.isEmpty(saveToFileOverwritingArg)
                        && StringUtils.isEmpty(saveToFileAppendingArg)) {
                    System.out.println(file.getName() + NAME_SEPARATOR + hash);
                }

            }

            if (!StringUtils.isEmpty(computeDirectoryFilesHashesArg)) {

                int factor = checkFactorArg(factorArg);
                File directory = new File(computeDirectoryFilesHashesArg);
                Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                        .computeNamedHashesFromDirectoryFiles(directory, factor, false);
                namesToHashes.putAll(namesToHashes1);

                if (StringUtils.isEmpty(saveToFileOverwritingArg)
                        && StringUtils.isEmpty(saveToFileAppendingArg)) {
                    for (String name : namesToHashes1.keySet()) {
                        System.out.println(name + NAME_SEPARATOR + namesToHashes1.get(name));
                    }
                }

            }

            if (!StringUtils.isEmpty(computeDirectoryFilesHashesNestedArg)) {

                int factor = checkFactorArg(factorArg);
                File directory = new File(computeDirectoryFilesHashesNestedArg);
                Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                        .computeNamedHashesFromDirectoryFiles(directory, factor, true);
                namesToHashes.putAll(namesToHashes1);

                if (StringUtils.isEmpty(saveToFileOverwritingArg)
                        && StringUtils.isEmpty(saveToFileAppendingArg)) {
                    for (String name : namesToHashes1.keySet()) {
                        System.out.println(name + NAME_SEPARATOR + namesToHashes1.get(name));
                    }
                }

            }

            // Save to file.
            if (!StringUtils.isEmpty(saveToFileOverwritingArg)) {

                File storageFile = new File(saveToFileOverwritingArg);
                UniformFuzzyHashes.saveToFile(namesToHashes, storageFile, false);

            }

            if (!StringUtils.isEmpty(saveToFileAppendingArg)) {

                File storageFile = new File(saveToFileAppendingArg);
                UniformFuzzyHashes.saveToFile(namesToHashes, storageFile, true);

            }

            // Represent file visually
            if (!StringUtils.isEmpty(representFileVisuallyArg)) {

                int factor = checkFactorArg(factorArg);
                File file = new File(representFileVisuallyArg);
                UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);

                VisualRepresentation.print(hash);

            }

            // Compare file.
            if (!StringUtils.isEmpty(compareFileArg)) {

                int factor = checkFactorArg(factorArg);
                File file1 = new File(compareFileArg);
                UniformFuzzyHash hash1 = new UniformFuzzyHash(file1, factor);

                // To file.
                if (!StringUtils.isEmpty(toFileArg)) {

                    File file2 = new File(toFileArg);
                    UniformFuzzyHash hash2 = new UniformFuzzyHash(file2, factor);

                    System.out.println(hash1.similarity(hash2));

                }

                // To file visually.
                if (!StringUtils.isEmpty(toFileVisuallyArg)) {

                    File file2 = new File(toFileVisuallyArg);
                    UniformFuzzyHash hash2 = new UniformFuzzyHash(file2, factor);

                    VisualRepresentation.printCompared(hash1, hash2);

                    System.out.println(hash1.similarity(hash2));

                }

                // To saved hashes.
                if (!StringUtils.isEmpty(toSavedHashesArg)) {

                    File storageFile = new File(toSavedHashesArg);
                    Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                            .loadFromFile(storageFile);

                    UniformFuzzyHashes.printSimilarities(file1.getName(), hash1, namesToHashes1,
                            StringUtils.isEmpty(sortingArg)
                                    ? null
                                    : SimilaritySortCriterias.valueOf(sortingArg));

                }

                // To directory files.
                if (!StringUtils.isEmpty(toDirectoryFilesArg)) {

                    File directory = new File(toDirectoryFilesArg);
                    Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                            .computeNamedHashesFromDirectoryFiles(directory, factor, false);

                    UniformFuzzyHashes.printSimilarities(file1.getName(), hash1, namesToHashes1,
                            StringUtils.isEmpty(sortingArg)
                                    ? null
                                    : SimilaritySortCriterias.valueOf(sortingArg));

                }

                // To directory files nested.
                if (!StringUtils.isEmpty(toDirectoryFilesNestedArg)) {

                    File directory = new File(toDirectoryFilesNestedArg);
                    Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                            .computeNamedHashesFromDirectoryFiles(directory, factor, true);

                    UniformFuzzyHashes.printSimilarities(file1.getName(), hash1, namesToHashes1,
                            StringUtils.isEmpty(sortingArg)
                                    ? null
                                    : SimilaritySortCriterias.valueOf(sortingArg));

                }

            }

            // Compare saved hashes.
            if (!StringUtils.isEmpty(compareSavedHashesArg)) {

                File storageFile = new File(compareSavedHashesArg);
                Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                        .loadFromFile(storageFile);

                UniformFuzzyHashes.printSimilarityTable(namesToHashes1);

            }

            // Compare directory files.
            if (!StringUtils.isEmpty(compareDirectoryFilesArg)) {

                int factor = checkFactorArg(factorArg);
                File directory = new File(compareDirectoryFilesArg);
                Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                        .computeNamedHashesFromDirectoryFiles(directory, factor, false);

                UniformFuzzyHashes.printSimilarityTable(namesToHashes1);

            }

            // Compare directory files nested.
            if (!StringUtils.isEmpty(compareDirectoryFilesNestedArg)) {

                int factor = checkFactorArg(factorArg);
                File directory = new File(compareDirectoryFilesNestedArg);
                Map<String, UniformFuzzyHash> namesToHashes1 = UniformFuzzyHashes
                        .computeNamedHashesFromDirectoryFiles(directory, factor, true);

                UniformFuzzyHashes.printSimilarityTable(namesToHashes1);

            }

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            System.exit(1);
        }

    }

    /**
     * Checks the factor argument.
     * 
     * @param factorArg The factor argument to check.
     * @return The parsed factor.
     */
    private static int checkFactorArg(String factorArg) {

        if (StringUtils.isEmpty(factorArg)) {
            throw new IllegalArgumentException("Please, introduce a factor.");
        }

        int factor = 0;

        try {
            factor = Integer.parseInt(factorArg);
        } catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException("Factor must be a number.");
        }

        return factor;

    }

}
