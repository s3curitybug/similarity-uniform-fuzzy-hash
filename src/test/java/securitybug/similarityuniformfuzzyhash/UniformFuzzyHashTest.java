package securitybug.similarityuniformfuzzyhash;

import static securitybug.similarityuniformfuzzyhash.ToStringUtils.DECIMALS_FORMAT;

import securitybug.similarityuniformfuzzyhash.UniformFuzzyHashes.HashCharacteristics;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

/**
 * Class to test the Uniform Fuzzy Hash.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public class UniformFuzzyHashTest {

    /**
     * Algorithm computation test.
     * Tests the algorithm computation over a test resource file and the hash toString and
     * toAsciiString methods.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void algorithmComputationTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("RandomText/RandomText1/B.txt");

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
        String hashString = hash.toString();
        String hashAsciiString = hash.toAsciiString();

        System.out.println(hashString);
        System.out.println(hashAsciiString);

    }

    /**
     * Hash rebuild test.
     * Tests the hash rebuild from a string representation of a hash computed over a test resource
     * file, and the hash equals method.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashRebuildTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("RandomText/RandomText1/B.txt");

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
        String hashString = hash.toString();

        UniformFuzzyHash rebuiltHash = UniformFuzzyHash.rebuildFromString(hashString);
        String rebuiltHashString = rebuiltHash.toString();

        Assert.assertTrue(hash.equals(rebuiltHash));
        Assert.assertTrue(hashString.equals(rebuiltHashString));

    }

    /**
     * Hash ascii rebuild test.
     * Tests the hash rebuild from an ascii string representation of a hash computed over a test
     * resource file, and the hash equals method.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashAsciiRebuildTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("RandomText/RandomText1/B.txt");

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
        String hashAsciiString = hash.toAsciiString();

        UniformFuzzyHash rebuiltHash = UniformFuzzyHash.rebuildFromAsciiString(hashAsciiString);
        String rebuiltHashAsciiString = rebuiltHash.toAsciiString();

        Assert.assertTrue(hash.equals(rebuiltHash));
        Assert.assertTrue(hashAsciiString.equals(rebuiltHashAsciiString));

    }

    /**
     * Hash characteristics test.
     * Tests the statistics of a hash computed over a test resource file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashCharacteristicsTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("RandomText/RandomText1/B.txt");
        final String statisticsFormat = "%s: %s";

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);

        for (HashCharacteristics statistic : HashCharacteristics.values()) {
            if (statistic.getGetter() != null) {
                System.out.println(String.format(
                        statisticsFormat,
                        statistic.getName(),
                        statistic.getCharaceristicValue(hash)));
            }
        }

    }

    /**
     * Similarity test.
     * Tests the similarity between two hashes computed over two test resource files.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void similarityTest()
            throws IOException {

        final int factor = 50001;
        final File file1 = TestResourcesUtils.getTestResourceFile("InsideDoc/Lenna.png");
        final File file2 = TestResourcesUtils.getTestResourceFile("InsideDoc/Doc_Lenna.docx");
        final boolean printHashes = true;

        UniformFuzzyHash hash1 = new UniformFuzzyHash(file1, factor);
        UniformFuzzyHash hash2 = new UniformFuzzyHash(file2, factor);

        double similarity1 = hash1.similarity(hash2);
        double similarity2 = hash1.reverseSimilarity(hash2);
        double maxSimilarity = hash1.maxSimilarity(hash2);
        double minSimilarity = hash1.minSimilarity(hash2);
        double arithmeticMean = hash1.arithmeticMeanSimilarity(hash2);
        double geometricMean = hash1.geometricMeanSimilarity(hash2);

        if (printHashes) {
            System.out.println(hash1);
            System.out.println(hash2);
        }

        System.out.println("File 1 to File 2 similarity: " + DECIMALS_FORMAT.format(similarity1));
        System.out.println("File 2 to File 1 similarity: " + DECIMALS_FORMAT.format(similarity2));
        System.out.println("Maximum similarity: " + DECIMALS_FORMAT.format(maxSimilarity));
        System.out.println("Minimum similarity: " + DECIMALS_FORMAT.format(minSimilarity));
        System.out.println("Arithmetic mean: " + DECIMALS_FORMAT.format(arithmeticMean));
        System.out.println("Geometric mean: " + DECIMALS_FORMAT.format(geometricMean));

    }

}
