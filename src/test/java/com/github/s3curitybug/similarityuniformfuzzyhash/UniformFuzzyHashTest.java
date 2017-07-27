package com.github.s3curitybug.similarityuniformfuzzyhash;

import org.junit.Assert;
import org.junit.Test;

import com.github.s3curitybug.similarityuniformfuzzyhash.UniformFuzzyHash.SimilarityTypes;

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
     * Tests the algorithm computation over a test resource file and the hash toString method.
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

        System.out.println(hashString);

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
     * Similarity test.
     * Tests all the similarity types between two hashes computed over two test resource files.
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

        if (printHashes) {
            System.out.println(hash1);
            System.out.println(hash2);
            System.out.println();
        }

        for (SimilarityTypes similarityType : SimilarityTypes.values()) {
            System.out.println(String.format(
                    "%s: %s",
                    similarityType.getName(),
                    ToStringUtils.formatDecimal(hash1.similarity(hash2, similarityType))));
        }

    }

}
