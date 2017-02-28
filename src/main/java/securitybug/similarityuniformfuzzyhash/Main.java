package securitybug.similarityuniformfuzzyhash;

import java.io.File;
import java.io.IOException;

/**
 * This class provides a main method to run the Uniform Fuzzy Hash jar via command line.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class Main {

    /**
     * Private constructor.
     */
    private Main() {

    }

    /**
     * Main method.
     * 
     * @param args Run arguments.
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        // TODO

        final int factor = new Integer(args[0]);

        UniformFuzzyHash hash1 = new UniformFuzzyHash(new File(args[1]), factor);
        UniformFuzzyHash hash2 = new UniformFuzzyHash(new File(args[2]), factor);

        VisualRepresentation.printCompared(hash1, hash2);

    }

}
