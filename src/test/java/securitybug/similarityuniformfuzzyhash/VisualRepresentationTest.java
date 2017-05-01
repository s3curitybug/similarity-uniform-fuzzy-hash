package securitybug.similarityuniformfuzzyhash;

import org.junit.Test;

import java.io.File;
import java.io.IOException;

/**
 * Class to test the visual representation of Uniform Fuzzy Hashes.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public class VisualRepresentationTest {

    /**
     * Hash visual representation test.
     * Tests the visual representation of a Uniform Fuzzy Hash computed over a test resource file.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashVisualRepresentationTest()
            throws IOException {

        final int factor = 11;
        final File file = TestResourcesUtils.getTestResourceFile("RandomText1/B.txt");

        UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);

        VisualRepresentation.print(hash);

    }

    /**
     * Hashes comparison visual representation test.
     * Tests the visual representation of a comparison between two Uniform Fuzzy Hashes computed
     * over two test resource files.
     * 
     * @throws IOException In case an exception occurs reading a test resource file.
     */
    @Test
    public void hashesComparisonVisualRepresentationTest()
            throws IOException {

        final int factor = 1001;
        final File file1 = TestResourcesUtils.getTestResourceFile("Images/Image1.bmp");
        final File file2 = TestResourcesUtils.getTestResourceFile("Images/Image2.bmp");

        UniformFuzzyHash hash1 = new UniformFuzzyHash(file1, factor);
        UniformFuzzyHash hash2 = new UniformFuzzyHash(file2, factor);

        VisualRepresentation.printCompared(hash1, hash2);

    }

}
