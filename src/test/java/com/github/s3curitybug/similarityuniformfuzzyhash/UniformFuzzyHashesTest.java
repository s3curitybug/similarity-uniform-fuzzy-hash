package com.github.s3curitybug.similarityuniformfuzzyhash;

import org.junit.Assert;
import org.junit.Test;

import com.github.s3curitybug.similarityuniformfuzzyhash.UniformFuzzyHash.SimilarityTypes;

import java.io.File;
import java.io.IOException;
import java.util.Map;

/**
 * Class to test Uniform Fuzzy Hashes.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public class UniformFuzzyHashesTest {

    /**
     * Hashes from directory files test.
     * Tests the algorithm computation over the files of a test resources directory and the
     * printHashes method.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashesFromDirectoryFilesTest()
            throws IOException {

        final int factor = 11;
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");

        Map<String, UniformFuzzyHash> hashes = UniformFuzzyHashes
                .computeHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.printHashes(hashes);

    }

    /**
     * Save and load hashes as text test.
     * Tests the hashes saving to and loading from a target text file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file or writing a
     *         target file.
     */
    @Test
    public void saveAndLoadHashesAsTextTest()
            throws IOException {

        final int factor = 11;
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");
        final File storageFile = TestResourcesUtils.getTargetFile(directory.getName() + ".sufh");

        Map<String, UniformFuzzyHash> hashes = UniformFuzzyHashes
                .computeHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.saveHashesToTextFile(hashes, storageFile, false);

        Assert.assertTrue(storageFile.exists());

        Map<String, UniformFuzzyHash> loadedHashes = UniformFuzzyHashes
                .loadHashesFromTextFile(storageFile);

        Assert.assertTrue(hashes.equals(loadedHashes));

    }

    /**
     * Similarities between file and directory files test.
     * Tests the similarities between a file and the files of a test resources directory, sorting
     * them by similarity, printing them in a table and saving them as a target CSV file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void similaritiesBetweenFileAndDirectoryFilesTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("LoremIpsum/ABCD.txt");
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");
        final File csvFile = TestResourcesUtils.getTargetFile(directory.getName() + ".csv");
        final SimilarityTypes sortCriterion = SimilarityTypes.SIMILARITY;
        final boolean sortAscending = false;
        final int rowsLimit = -1;
        final int truncateIdentifiers = 14;
        final double markAbove = -1;
        final double markBelow = -1;

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);

        Map<String, UniformFuzzyHash> hashes = UniformFuzzyHashes
                .computeHashesFromDirectoryFiles(directory, factor, true);

        Map<String, Map<SimilarityTypes, Double>> similarities = UniformFuzzyHashes
                .computeHashToHashesSimilarities(hash, hashes);

        Map<String, Map<SimilarityTypes, Double>> sortedSimilarities = UniformFuzzyHashes
                .sortSimilarities(similarities, sortCriterion, sortAscending);

        UniformFuzzyHashes.printHashToHashesSimilaritiesTable(
                sortedSimilarities, rowsLimit, truncateIdentifiers, markAbove, markBelow);

        UniformFuzzyHashes.saveHashToHashesSimilaritiesAsCsv(
                sortedSimilarities, csvFile, rowsLimit);

        Assert.assertTrue(csvFile.exists());

    }

    /**
     * Similarities between all directory files test.
     * Tests the similarities between all the files of a test resources directory, printing them in
     * a table and saving them as a target CSV file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void similaritiesBetweenAllDirectoryFilesTest()
            throws IOException {

        final int factor = 11;
        final File directory = TestResourcesUtils.getTestResourceFile("InsideDoc");
        final File csvFile = TestResourcesUtils.getTargetFile(directory.getName() + ".csv");
        final int truncateIdentifiers = 14;
        final double markAbove = -1;
        final double markBelow = -1;

        Map<String, UniformFuzzyHash> hashes = UniformFuzzyHashes
                .computeHashesFromDirectoryFiles(directory, factor, true);

        Map<String, Map<String, Double>> similarities = UniformFuzzyHashes
                .computeAllHashesSimilarities(hashes);

        UniformFuzzyHashes.printAllHashesSimilaritiesTable(
                similarities, truncateIdentifiers, markAbove, markBelow);

        UniformFuzzyHashes.saveAllHashesSimilaritiesAsCsv(
                similarities, csvFile);

        Assert.assertTrue(csvFile.exists());

    }

}
