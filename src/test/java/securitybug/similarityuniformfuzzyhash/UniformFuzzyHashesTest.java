package securitybug.similarityuniformfuzzyhash;

import securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.SimilarityTypes;

import org.junit.Assert;
import org.junit.Test;

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
     * Tests the algorithm computation over the files of a test resources directory, and the
     * printHashesTable method.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashesFromDirectoryFilesTest()
            throws IOException {

        final int factor = 10;
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");
        final int truncateNamesLength = 8;

        Map<String, UniformFuzzyHash> namesToHashes = UniformFuzzyHashes
                .computeNamedHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.printHashesTable(namesToHashes, true, true, truncateNamesLength);

    }

    /**
     * Similarities between all directory files test.
     * Tests the similarities between all the files of a test resources directory.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void similaritiesBetweenAllDirectoryFilesTest()
            throws IOException {

        final int factor = 10;
        final File directory = TestResourcesUtils.getTestResourceFile("InsideDoc");
        final int truncateNamesLength = 8;

        Map<String, UniformFuzzyHash> namesToHashes = UniformFuzzyHashes
                .computeNamedHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.printAllHashesSimilaritiesTable(namesToHashes, truncateNamesLength);

    }

    /**
     * Similarities between file and directory files test.
     * Tests the similarities between a file and the files of a test resources directory, sorting
     * them by similarity.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void similaritiesBetweenFileAndDirectoryFilesTest()
            throws IOException {

        final int factor = 10;
        final File file = TestResourcesUtils.getTestResourceFile("LoremIpsum/ABCD.txt");
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");
        final SimilarityTypes sortCriteria = SimilarityTypes.SIMILARITY;
        final boolean sortAscending = false;
        final int rowsLimit = -1;
        final int truncateNamesLength = 8;

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);

        Map<String, UniformFuzzyHash> namesToHashes = UniformFuzzyHashes
                .computeNamedHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.printHashToHashesSimilaritiesTable(
                hash, namesToHashes, sortCriteria, sortAscending, rowsLimit, truncateNamesLength);

    }

    /**
     * Save and load hashes test.
     * Tests the hashes saving to and loading from a file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void saveAndLoadHashesTest()
            throws IOException {

        final int factor = 10;
        final File directory = TestResourcesUtils.getTestResourceFile("LoremIpsum");
        final File storageFile = TestResourcesUtils.getTargetFile(directory.getName() + ".sufh");

        Map<String, UniformFuzzyHash> namesToHashes = UniformFuzzyHashes
                .computeNamedHashesFromDirectoryFiles(directory, factor, true);

        UniformFuzzyHashes.saveToFile(namesToHashes, storageFile, false);

        Assert.assertTrue(storageFile.exists());

        Map<String, UniformFuzzyHash> loadedNamesToHashes = UniformFuzzyHashes
                .loadFromFile(storageFile);

        Assert.assertTrue(namesToHashes.equals(loadedNamesToHashes));

    }

}
