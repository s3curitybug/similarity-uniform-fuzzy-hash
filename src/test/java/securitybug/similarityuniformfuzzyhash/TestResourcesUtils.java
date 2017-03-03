package securitybug.similarityuniformfuzzyhash;

import java.io.File;

/**
 * This class provides utility methods and constants to use resources in tests.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class TestResourcesUtils {

    /**
     * Path to test resources directory.
     */
    public static final String TEST_RESOURCES_PATH = "src/test/resources/";

    /**
     * Path to target directory.
     */
    public static final String TARGET_PATH = "target/";

    /**
     * Private constuctror.
     */
    private TestResourcesUtils() {

    }

    /**
     * @param fileName A test resource file name.
     * @return The test resource file.
     */
    public static File getTestResourceFile(
            String fileName) {

        return new File(TEST_RESOURCES_PATH + fileName);

    }

    /**
     * @param fileName A target file name.
     * @return The target file.
     */
    public static File getTargetFile(
            String fileName) {

        return new File(TARGET_PATH + fileName);

    }

}
