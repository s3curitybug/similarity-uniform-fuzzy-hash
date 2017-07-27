package com.github.s3curitybug.similarityuniformfuzzyhash;

import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.CSV_TRIMMED_SEPARATOR;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.FILES_ENCODING;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.IDENTIFIER_SEPARATOR;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.IGNORE_MARK;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.TAB;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.ZERO_TO_ONE_DECIMAL_MAX_CHARS;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.escapeCsv;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.formatDecimal;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.hyphens;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.maxLength;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.prepareIdentifier;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.prepareIdentifiers;
import static com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.spaces;

import org.apache.commons.io.output.FileWriterWithEncoding;
import org.fusesource.jansi.AnsiConsole;

import com.github.s3curitybug.similarityuniformfuzzyhash.ToStringUtils.AnsiCodeColors;
import com.github.s3curitybug.similarityuniformfuzzyhash.UniformFuzzyHash.SimilarityTypes;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * This class provides utility static methods related to the Uniform Fuzzy Hash usage.
 * 
 * @author s3curitybug@gmail.com
 *
 */
public final class UniformFuzzyHashes {

    /**
     * Private constructor.
     */
    private UniformFuzzyHashes() {

    }

    /**
     * Builds a map of identified objects from a collection of objects,
     * identifying them by their index in the collection.
     * 
     * @param <S> Objects type.
     * @param objects Collection of objects.
     * @return Map of identified objects.
     */
    public static <S> Map<Integer, S> collectionToMap(
            Collection<S> objects) {

        if (objects == null) {
            throw new NullPointerException("Collection is null.");
        }

        Map<Integer, S> identifiedObjects = new LinkedHashMap<>(objects.size());

        int i = 0;
        for (S object : objects) {
            identifiedObjects.put(i++, object);
        }

        return identifiedObjects;

    }

    /**
     * Builds a list of objects from a map of identified objects.
     * 
     * @param <T> Identifiers type.
     * @param <S> Objects type.
     * @param identifiedObjects Map of identified objects.
     * @return List of objects.
     */
    public static <T, S> List<S> mapValuesToList(
            Map<T, S> identifiedObjects) {

        if (identifiedObjects == null) {
            throw new NullPointerException("Map is null.");
        }

        return new ArrayList<>(identifiedObjects.values());

    }

    /**
     * Builds a list of identifiers from a map of identified objects.
     * 
     * @param <T> Identifiers type.
     * @param <S> Objects type.
     * @param identifiedObjects Map of identified objects.
     * @return List of identifiers.
     */
    public static <T, S> List<T> mapKeysToList(
            Map<T, S> identifiedObjects) {

        if (identifiedObjects == null) {
            throw new NullPointerException("Map is null.");
        }

        return new ArrayList<>(identifiedObjects.keySet());

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a map of identified byte arrays of
     * data and a factor.
     * 
     * @param <T> Identifiers type.
     * @param byteArrays Map of identified byte arrays of data.
     * @param factor Relation between data length and the hash mean number of blocks for each byte
     *        array of data. Must be greater than 2 and must be odd.
     * @return Map of identified Uniform Fuzzy Hashes.
     */
    public static <T> Map<T, UniformFuzzyHash> computeHashesFromByteArrays(
            Map<T, byte[]> byteArrays,
            int factor) {

        if (byteArrays == null) {
            throw new NullPointerException("Map of byte arrays is null.");
        }

        Set<Entry<T, byte[]>> entries = byteArrays.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, byte[]> entry : entries) {

            T identifier = entry.getKey();
            byte[] byteArray = entry.getValue();

            if (byteArray == null) {
                hashes.put(identifier, null);
                continue;
            }

            UniformFuzzyHash hash = new UniformFuzzyHash(byteArray, factor);
            hashes.put(identifier, hash);

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a map of identified strings of data
     * (using the platform's default charset) and a factor.
     * 
     * @param <T> Identifiers type.
     * @param strings Map of identified strings of data.
     * @param factor Relation between data length and the hash mean number of blocks for each string
     *        of data. Must be greater than 2 and must be odd.
     * @return Map of identified Uniform Fuzzy Hashes.
     */
    public static <T> Map<T, UniformFuzzyHash> computeHashesFromStrings(
            Map<T, String> strings,
            int factor) {

        if (strings == null) {
            throw new NullPointerException("Map of strings is null.");
        }

        Set<Entry<T, String>> entries = strings.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, String> entry : entries) {

            T identifier = entry.getKey();
            String string = entry.getValue();

            if (string == null) {
                hashes.put(identifier, null);
                continue;
            }

            UniformFuzzyHash hash = new UniformFuzzyHash(string, factor);
            hashes.put(identifier, hash);

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a map of identified input streams of
     * data and a factor.
     * 
     * @param <T> Identifiers type.
     * @param inputStreams Map of identified input streams of data.
     * @param factor Relation between data length and the hash mean number of blocks for each input
     *        stream of data. Must be greater than 2 and must be odd.
     * @return Map of identified Uniform Fuzzy Hashes.
     * @throws IOException If an IOException occurs reading any of the input streams of data.
     */
    public static <T> Map<T, UniformFuzzyHash> computeHashesFromInputStreams(
            Map<T, InputStream> inputStreams,
            int factor)
            throws IOException {

        if (inputStreams == null) {
            throw new NullPointerException("Map of input streams is null.");
        }

        Set<Entry<T, InputStream>> entries = inputStreams.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, InputStream> entry : entries) {

            T identifier = entry.getKey();
            InputStream inputStream = entry.getValue();

            if (inputStream == null) {
                hashes.put(identifier, null);
                continue;
            }

            UniformFuzzyHash hash = new UniformFuzzyHash(inputStream, factor);
            hashes.put(identifier, hash);

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a map of identified byte array output
     * streams of data and a factor.
     * 
     * @param <T> Identifiers type.
     * @param byteArrayOutputStreams Map of identified byte array output streams of data.
     * @param factor Relation between data length and the hash mean number of blocks for each input
     *        stream of data. Must be greater than 2 and must be odd.
     * @return Map of identified Uniform Fuzzy Hashes.
     */
    public static <T> Map<T, UniformFuzzyHash> computeHashesFromByteArrayOutputStreams(
            Map<T, ByteArrayOutputStream> byteArrayOutputStreams,
            int factor) {

        if (byteArrayOutputStreams == null) {
            throw new NullPointerException("Map of byte array output streams is null.");
        }

        Set<Entry<T, ByteArrayOutputStream>> entries = byteArrayOutputStreams.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, ByteArrayOutputStream> entry : entries) {

            T identifier = entry.getKey();
            ByteArrayOutputStream byteArrayOutputStream = entry.getValue();

            if (byteArrayOutputStream == null) {
                hashes.put(identifier, null);
                continue;
            }

            UniformFuzzyHash hash = new UniformFuzzyHash(byteArrayOutputStream, factor);
            hashes.put(identifier, hash);

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a map of identified files of data and
     * a factor. Files which do not exist and directories are ignored.
     * 
     * @param <T> Identifiers type.
     * @param files Map of identified files of data.
     * @param factor Relation between data length and the hash mean number of blocks for each file
     *        of data. Must be greater than 2 and must be odd.
     * @return Map of identified Uniform Fuzzy Hashes.
     * @throws IOException If an IOException occurs reading any of the files of data.
     */
    public static <T> Map<T, UniformFuzzyHash> computeHashesFromFiles(
            Map<T, File> files,
            int factor)
            throws IOException {

        if (files == null) {
            throw new NullPointerException("Map of files is null.");
        }

        Set<Entry<T, File>> entries = files.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, File> entry : entries) {

            T identifier = entry.getKey();
            File file = entry.getValue();

            if (file == null) {
                hashes.put(identifier, null);
                continue;
            }

            if (file.exists() && file.isFile()) {
                UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
                hashes.put(identifier, hash);
            }

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from a collection of files of data
     * (identifying them by their names) and a factor. Files which do not exist are ignored.
     * 
     * @param files Collection of files of data.
     * @param factor Relation between data length and the hash mean number of blocks for each file
     *        of data. Must be greater than 2 and must be odd.
     * @param nested True to read files inside directories recursively. False to ignore directories.
     * @return Map of identified Uniform Fuzzy Hashes.
     * @throws IOException If an IOException occurs reading any of the files of data.
     */
    public static Map<String, UniformFuzzyHash> computeHashesFromFiles(
            Collection<File> files,
            int factor,
            boolean nested)
            throws IOException {

        if (files == null) {
            throw new NullPointerException("Collection of files is null.");
        }

        Map<String, UniformFuzzyHash> hashes = new LinkedHashMap<>(files.size());

        for (File file : files) {

            if (file == null) {
                hashes.put(null, null);
                continue;
            }

            if (file.exists()) {
                if (file.isFile()) {
                    UniformFuzzyHash hash = new UniformFuzzyHash(file, factor);
                    hashes.put(file.getName(), hash);
                } else if (file.isDirectory() && nested) {
                    Map<String, UniformFuzzyHash> nestedHashes = computeHashesFromFiles(
                            Arrays.asList(file.listFiles()), factor, nested);
                    hashes.putAll(nestedHashes);
                }
            }

        }

        return hashes;

    }

    /**
     * Computes a map of identified Uniform Fuzzy Hashes from the files inside a directory
     * (identifying them by their names) and a factor. Files which do not exist are ignored.
     * 
     * @param directory Directory of files.
     * @param factor Relation between data length and the hash mean number of blocks for each file
     *        of data. Must be greater than 2 and must be odd.
     * @param nested True to read files inside directories recursively. False to ignore directories.
     * @return Map of identified Uniform Fuzzy Hashes.
     * @throws IOException If an IOException occurs reading any of the files of data.
     */
    public static Map<String, UniformFuzzyHash> computeHashesFromDirectoryFiles(
            File directory,
            int factor,
            boolean nested)
            throws IOException {

        if (directory == null) {
            throw new NullPointerException("Directory is null.");
        }

        if (!directory.exists()) {
            throw new IllegalArgumentException(String.format(
                    "Directory %s does not exist.",
                    directory.getName()));
        }

        if (!directory.isDirectory()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a directory.",
                    directory.getName()));
        }

        List<File> files = Arrays.asList(directory.listFiles());
        return computeHashesFromFiles(files, factor, nested);

    }

    /**
     * Builds a map of identified strings representing Uniform Fuzzy Hashes from a map of identified
     * Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     * @return Map of identified strings representing the hashes.
     */
    public static <T> Map<T, String> hashesToStrings(
            Map<T, UniformFuzzyHash> hashes) {

        if (hashes == null) {
            throw new NullPointerException("Map of hashes is null.");
        }

        Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();
        Map<T, String> strings = new LinkedHashMap<>(entries.size());

        for (Entry<T, UniformFuzzyHash> entry : entries) {

            T identifier = entry.getKey();
            UniformFuzzyHash hash = entry.getValue();

            if (hash == null) {
                strings.put(identifier, null);
                continue;
            }

            String hashString = hash.toString();
            strings.put(identifier, hashString);

        }

        return strings;

    }

    /**
     * Builds a text line representing an identified Uniform Fuzzy Hash.
     * 
     * @param <T> Identifier type.
     * @param identifier The Uniform Fuzzy Hash identifier.
     * @param hash The Uniform Fuzzy Hash.
     * @return Text line representing the identified hash.
     */
    public static <T> String hashToTextLine(
            T identifier,
            UniformFuzzyHash hash) {

        if (hash == null) {
            throw new NullPointerException("Hash is null.");
        }

        String identifierString = prepareIdentifier(identifier, -1);
        String hashString = hash.toString();

        return identifierString + IDENTIFIER_SEPARATOR + hashString;

    }

    /**
     * Builds a list of text lines representing Uniform Fuzzy Hashes from a map of identified
     * Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     * @return List of text lines representing the identified hashes.
     */
    public static <T> List<String> hashesToTextLines(
            Map<T, UniformFuzzyHash> hashes) {

        if (hashes == null) {
            throw new NullPointerException("Map of hashes is null.");
        }

        Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();
        List<String> textLines = new ArrayList<>(entries.size());

        for (Entry<T, UniformFuzzyHash> entry : entries) {

            T identifier = entry.getKey();
            UniformFuzzyHash hash = entry.getValue();

            if (hash == null) {
                textLines.add(null);
                continue;
            }

            String textLine = hashToTextLine(identifier, hash);
            textLines.add(textLine);

        }

        return textLines;

    }

    /**
     * Rebuilds a map of identified Uniform Fuzzy Hashes from a map of identified strings
     * representing them.
     * 
     * @param <T> Identifiers type.
     * @param strings Map of identified strings representing Uniform Fuzzy Hashes.
     * @return Map of identified Uniform Fuzzy Hashes.
     */
    public static <T> Map<T, UniformFuzzyHash> rebuildHashesFromStrings(
            Map<T, String> strings) {

        if (strings == null) {
            throw new NullPointerException("Map of hash strings is null.");
        }

        Set<Entry<T, String>> entries = strings.entrySet();
        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(entries.size());

        for (Entry<T, String> entry : entries) {

            T identifier = entry.getKey();
            String hashString = entry.getValue();

            if (hashString == null) {
                hashes.put(identifier, null);
                continue;
            }

            UniformFuzzyHash hash = null;
            try {
                hash = UniformFuzzyHash.rebuildFromString(hashString);
            } catch (IllegalArgumentException illegalArgumentException) {
                throw new IllegalArgumentException(String.format(
                        "Hash %s could not be parsed. %s",
                        identifier,
                        illegalArgumentException.getMessage()));
            }
            hashes.put(identifier, hash);

        }

        return hashes;

    }

    /**
     * Rebuilds an identified Uniform Fuzzy Hash from a text line representing it and adds it to a
     * map of identified Uniform Fuzzy Hashes.
     * 
     * @param textLine Text line representing an identified Uniform Fuzzy Hash.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     */
    public static void rebuildHashFromTextLine(
            String textLine,
            Map<String, UniformFuzzyHash> hashes) {

        if (textLine == null) {
            throw new NullPointerException("Text line is null.");
        }

        if (hashes == null) {
            throw new NullPointerException("Map of hashes is null.");
        }

        // Check empty line and ignore mark.
        if (textLine.isEmpty() || textLine.startsWith(IGNORE_MARK)) {
            return;
        }

        // Split identifier from hash.
        int splitIndex = textLine.indexOf(IDENTIFIER_SEPARATOR.trim());

        if (splitIndex < 0) {
            throw new IllegalArgumentException(String.format(
                    "Line does not fit the format identifier%shash.",
                    IDENTIFIER_SEPARATOR));
        }

        // Identifier.
        String identifier = textLine.substring(0, splitIndex).trim();
        identifier = prepareIdentifier(identifier, -1);

        // Hash.
        String hashString = textLine.substring(splitIndex + 1).trim();

        if (hashString.isEmpty()) {
            throw new IllegalArgumentException(String.format(
                    "Line does not fit the format name%shash.",
                    IDENTIFIER_SEPARATOR));
        }

        UniformFuzzyHash hash = null;

        try {
            hash = UniformFuzzyHash.rebuildFromString(hashString);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new IllegalArgumentException(String.format(
                    "Line hash (name: %s) could not be parsed. %s",
                    identifier.isEmpty() ? "<empty>" : identifier,
                    illegalArgumentException.getMessage()));
        }

        hashes.put(identifier, hash);

    }

    /**
     * Rebuilds a map of identified Uniform Fuzzy Hashes from a collection of text lines
     * representing them.
     * 
     * @param textLines Collection of text lines representing identified Uniform Fuzzy Hashes.
     * @return Map of identified Uniform Fuzzy Hashes.
     */
    public static Map<String, UniformFuzzyHash> rebuildHashesFromTextLines(
            Collection<String> textLines) {

        if (textLines == null) {
            throw new NullPointerException("Collection of text lines is null.");
        }

        Map<String, UniformFuzzyHash> hashes = new LinkedHashMap<>(textLines.size());

        int i = 0;
        for (String textLine : textLines) {

            if (textLine == null) {
                hashes.put(null, null);
                continue;
            }

            try {
                rebuildHashFromTextLine(textLine, hashes);
            } catch (IllegalArgumentException illegalArgumentException) {
                throw new IllegalArgumentException(String.format(
                        "Line number %d could not be parsed. %s",
                        i,
                        illegalArgumentException.getMessage()));
            }

            i++;

        }

        return hashes;

    }

    /**
     * Writes an identified Uniform Fuzzy Hash into a text file.
     * 
     * @param <T> Identifiers type.
     * @param identifier The Uniform Fuzzy Hash identifier.
     * @param hash The Uniform Fuzzy Hash.
     * @param file The file to save the hash.
     * @param append True to append the hash at the end of the file. False to overwrite the file.
     * @throws IOException If an IOException occurs writing into the file.
     */
    public static <T> void saveHashToTextFile(
            T identifier,
            UniformFuzzyHash hash,
            File file,
            boolean append)
            throws IOException {

        if (hash == null) {
            throw new NullPointerException("Hash is null.");
        }

        Map<T, UniformFuzzyHash> hashes = new LinkedHashMap<>(1);
        hashes.put(identifier, hash);

        saveHashesToTextFile(hashes, file, append);

    }

    /**
     * Writes a map of identified Uniform Fuzzy Hashes into a text file.
     * 
     * @param <T> Identifiers type.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     * @param file The file to save the hashes.
     * @param append True to append the hashes at the end of the file. False to overwrite the file.
     * @throws IOException If an IOException occurs writing into the file.
     */
    public static <T> void saveHashesToTextFile(
            Map<T, UniformFuzzyHash> hashes,
            File file,
            boolean append)
            throws IOException {

        if (hashes == null) {
            throw new NullPointerException("Map of hashes is null.");
        }

        if (file == null) {
            throw new NullPointerException("File is null.");
        }

        if (file.exists() && !file.isFile()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a file.",
                    file.getName()));
        }

        try (PrintWriter writer = new PrintWriter(new FileWriterWithEncoding(
                file, FILES_ENCODING, append))) {

            Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();

            for (Entry<T, UniformFuzzyHash> entry : entries) {

                T identifier = entry.getKey();
                UniformFuzzyHash hash = entry.getValue();

                if (hash == null) {
                    writer.println();
                    continue;
                }

                String textLine = hashToTextLine(identifier, hash);
                writer.println(textLine);

            }

        }

    }

    /**
     * Loads a map of identified Uniform Fuzzy Hashes from a text file.
     * Lines starting by # are ignored.
     * 
     * @param file The file to load the hashes.
     * @return Map of identified Uniform Fuzzy Hashes.
     * @throws IOException IOException If an IOException occurs reading from the file.
     */
    public static Map<String, UniformFuzzyHash> loadHashesFromTextFile(
            File file)
            throws IOException {

        if (file == null) {
            throw new NullPointerException("File is null.");
        }

        if (!file.exists()) {
            throw new IllegalArgumentException(String.format(
                    "File %s does not exist.",
                    file.getName()));
        }

        if (!file.isFile()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a file.",
                    file.getName()));
        }

        Map<String, UniformFuzzyHash> hashes = new LinkedHashMap<>();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(
                file), FILES_ENCODING))) {

            int lineNumber = 1;
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {

                try {
                    rebuildHashFromTextLine(line, hashes);
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new IllegalArgumentException(String.format(
                            "File %s could not be parsed. Line number %d could not be parsed. %s",
                            file.getName(),
                            lineNumber,
                            illegalArgumentException.getMessage()));
                }

                lineNumber++;

            }

        }

        return hashes;

    }

    /**
     * Computes all the types of similarity between a Uniform Fuzzy Hash and a map of identified
     * Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param hash A Uniform Fuzzy Hash.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     * @return Map of identified similarities.
     */
    public static <T> Map<T, Map<SimilarityTypes, Double>> computeHashToHashesSimilarities(
            UniformFuzzyHash hash,
            Map<T, UniformFuzzyHash> hashes) {

        Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();
        Map<T, Map<SimilarityTypes, Double>> similarities = new LinkedHashMap<>(entries.size());

        for (Entry<T, UniformFuzzyHash> entry : entries) {

            T identifier = entry.getKey();
            UniformFuzzyHash hash1 = entry.getValue();

            if (hash1 == null) {
                similarities.put(identifier, null);
                continue;
            }

            Map<SimilarityTypes, Double> similarities1 = hash.similarities(hash1);
            similarities.put(identifier, similarities1);

        }

        return similarities;

    }

    /**
     * Sorts a map of identified similarities by a type of similarity.
     * 
     * @param <T> Identifiers type.
     * @param similarities Map of identified similarities.
     * @param sortCriterion Type of similarity which will be used as sort criterion.
     * @param sortAscending True to sort ascending, false to sort descending.
     * @return Sorted map of identified similarities.
     */
    public static <T> Map<T, Map<SimilarityTypes, Double>> sortSimilarities(
            Map<T, Map<SimilarityTypes, Double>> similarities,
            SimilarityTypes sortCriterion,
            boolean sortAscending) {

        if (similarities == null) {
            throw new NullPointerException("Map of similarities is null.");
        }

        if (sortCriterion == null) {
            throw new NullPointerException("Similarity sort criterion is null.");
        }

        List<Entry<T, Map<SimilarityTypes, Double>>> entries =
                new ArrayList<>(similarities.entrySet());

        Collections.sort(entries, new Comparator<Entry<T, Map<SimilarityTypes, Double>>>() {

            @Override
            public int compare(
                    Entry<T, Map<SimilarityTypes, Double>> entry1,
                    Entry<T, Map<SimilarityTypes, Double>> entry2) {

                Map<SimilarityTypes, Double> similarities1 = entry1.getValue();
                Map<SimilarityTypes, Double> similarities2 = entry2.getValue();

                if (similarities1 == null && similarities2 == null) {
                    return 0;
                } else if (similarities1 == null) {
                    return 1;
                } else if (similarities2 == null) {
                    return -1;
                }

                Double similarity1 = similarities1.get(sortCriterion);
                Double similarity2 = similarities2.get(sortCriterion);

                if (similarity1 == null && similarity2 == null) {
                    return 0;
                } else if (similarity1 == null) {
                    return 1;
                } else if (similarity2 == null) {
                    return -1;
                }

                if (sortAscending) {
                    return similarity1.compareTo(similarity2);
                } else {
                    return similarity2.compareTo(similarity1);
                }

            }

        });

        Map<T, Map<SimilarityTypes, Double>> sortedSimilarities =
                new LinkedHashMap<>(entries.size());

        for (Entry<T, Map<SimilarityTypes, Double>> entry : entries) {
            sortedSimilarities.put(entry.getKey(), entry.getValue());
        }

        return sortedSimilarities;

    }

    /**
     * Sorts a map of identified objects by the order of another map.
     * 
     * @param <T> Identifiers type.
     * @param <S> Objects type.
     * @param identifiedObjects Map of identified objects.
     * @param sortedMap Sorted map which will be used to sort the map of identified objects.
     * @return Sorted map of identified objects.
     */
    public static <T, S> Map<T, S> sortMap(
            Map<T, S> identifiedObjects,
            Map<T, ?> sortedMap) {

        Map<T, S> sortedIdentifiedObjects = new LinkedHashMap<>(sortedMap.size());
        Set<T> keys = sortedMap.keySet();

        for (T key : keys) {
            sortedIdentifiedObjects.put(key, identifiedObjects.get(key));
        }

        return sortedIdentifiedObjects;

    }

    /**
     * Computes the similarity between all the hashes in a map of identified Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     * @return Map of identified similarities.
     */
    public static <T> Map<T, Map<T, Double>> computeAllHashesSimilarities(
            Map<T, UniformFuzzyHash> hashes) {

        Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();
        Map<T, Map<T, Double>> similarities = new LinkedHashMap<>(entries.size());

        for (Entry<T, UniformFuzzyHash> entry1 : entries) {

            T identifier1 = entry1.getKey();
            UniformFuzzyHash hash1 = entry1.getValue();

            Map<T, Double> similarities1 = new LinkedHashMap<>(entries.size());
            similarities.put(identifier1, similarities1);

            for (Entry<T, UniformFuzzyHash> entry2 : entries) {

                T identifier2 = entry2.getKey();
                UniformFuzzyHash hash2 = entry2.getValue();

                if (hash1 == null || hash2 == null) {
                    similarities1.put(identifier2, null);
                    continue;
                }

                double similarity = hash1.similarity(hash2);
                similarities1.put(identifier2, similarity);

            }

        }

        return similarities;

    }

    /**
     * Prints a map of identified Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param hashes Map of identified Uniform Fuzzy Hashes.
     */
    public static <T> void printHashes(
            Map<T, UniformFuzzyHash> hashes) {

        // Parameters check.
        if (hashes == null) {
            throw new NullPointerException("Map of hashes is null.");
        }

        if (hashes.isEmpty()) {
            return;
        }

        // Print.
        final PrintStream printStream = System.out;

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemInstall();
        }

        Set<Entry<T, UniformFuzzyHash>> entries = hashes.entrySet();

        for (Entry<T, UniformFuzzyHash> entry : entries) {

            T identifier = entry.getKey();
            UniformFuzzyHash hash = entry.getValue();

            if (hash == null) {
                printStream.println();
                continue;
            }

            String line = hashToTextLine(identifier, hash);
            printStream.println(line);

        }

        printStream.println();

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemUninstall();
        }

    }

    /**
     * Prints a table showing all the types of similarity between a Uniform Fuzzy Hash and a map of
     * identified Uniform Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param similarities Map of identified similarities (As it is returned from the method
     *        computeHashToHashesSimilarities).
     * @param rowsLimit Introduce a number larger than 0 to limit the number of rows.
     * @param truncateIdentifiers Introduce a number larger than 0 to truncate the identifiers to a
     *        maximum length.
     * @param markAbove Mark all similarities above or equal to this threshold with a color.
     *        Introduce a negative number to not mark any similarity.
     * @param markBelow Mark all similarities below this threshold with a color. Introduce a
     *        negative number to not mark any similarity.
     */
    public static <T> void printHashToHashesSimilaritiesTable(
            Map<T, Map<SimilarityTypes, Double>> similarities,
            int rowsLimit,
            int truncateIdentifiers,
            double markAbove,
            double markBelow) {

        // Parameters check.
        if (similarities == null) {
            throw new NullPointerException("Map of similarities is null.");
        }

        if (similarities.isEmpty()) {
            return;
        }

        // Identifiers.
        Set<T> identifiers = similarities.keySet();
        List<String> preparedIdentifiers = prepareIdentifiers(identifiers, truncateIdentifiers);
        int identifiersMaxLength = maxLength(preparedIdentifiers);

        // Similarity types names.
        List<String> similarityTypesNames = SimilarityTypes.names();
        int simiarityTypesNamesMaxLength = maxLength(similarityTypesNames);

        // Columns size.
        int firstColumnSize = getColumnSize(identifiersMaxLength);
        int columnSize = getColumnSize(ZERO_TO_ONE_DECIMAL_MAX_CHARS, simiarityTypesNamesMaxLength);

        // Table print.
        final PrintStream printStream;

        if (markAbove >= 0 || markBelow >= 0) {
            printStream = AnsiConsole.out;
        } else {
            printStream = System.out;
        }

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemInstall();
        }

        printStream.println();

        printFirstColumn("", firstColumnSize, printStream);
        for (String similarityTypeName : similarityTypesNames) {
            printColumn(similarityTypeName, columnSize, printStream);
        }
        printStream.println();

        printFirstRowSeparator(
                firstColumnSize, columnSize, similarityTypesNames.size(), printStream);

        int i = 0;
        Set<Entry<T, Map<SimilarityTypes, Double>>> entries = similarities.entrySet();
        for (Entry<T, Map<SimilarityTypes, Double>> entry : entries) {

            Map<SimilarityTypes, Double> similarities1 = entry.getValue();

            String preparedIdentifier = preparedIdentifiers.get(i);
            printFirstColumn(preparedIdentifier, firstColumnSize, printStream);
            for (SimilarityTypes similarityType : SimilarityTypes.values()) {
                Double similarity = null;
                if (similarities1 != null) {
                    similarity = similarities1.get(similarityType);
                }
                printColumn(formatDecimal(similarity, markAbove, markBelow),
                        columnSize, printStream);
            }
            printStream.println();

            if (i == rowsLimit - 1) {
                break;
            }

            i++;

        }

        printStream.println();

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemUninstall();
        }

    }

    /**
     * Writes a table showing all the types of similarity between a Uniform Fuzzy Hash and a map of
     * identified Uniform Fuzzy Hashes into a CSV file, overwriting it.
     * 
     * @param <T> Identifiers type.
     * @param similarities Map of identified similarities (As it is returned from the method
     *        computeHashToHashesSimilarities).
     * @param csvFile The file to save the CSV.
     * @param rowsLimit Introduce a number larger than 0 to limit the number of rows.
     * @throws IOException If an IOException occurs writing into the file.
     */
    public static <T> void saveHashToHashesSimilaritiesAsCsv(
            Map<T, Map<SimilarityTypes, Double>> similarities,
            File csvFile,
            int rowsLimit)
            throws IOException {

        // Parameters check.
        if (similarities == null) {
            throw new NullPointerException("Map of similarities is null.");
        }

        if (similarities.isEmpty()) {
            return;
        }

        if (csvFile == null) {
            throw new NullPointerException("CSV file is null.");
        }

        if (csvFile.exists() && !csvFile.isFile()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a file.",
                    csvFile.getName()));
        }

        // Identifiers.
        Set<T> identifiers = similarities.keySet();
        List<String> preparedIdentifiers = prepareIdentifiers(identifiers, -1);
        int identifiersMaxLength = maxLength(preparedIdentifiers);

        // Similarity types names.
        List<String> similarityTypesNames = SimilarityTypes.names();
        int simiarityTypesNamesMaxLength = maxLength(similarityTypesNames);

        // Generate CSV.
        try (PrintWriter writer = new PrintWriter(new FileWriterWithEncoding(
                csvFile, FILES_ENCODING, false))) {

            StringBuilder csvLine = null;

            csvLine = new StringBuilder((CSV_TRIMMED_SEPARATOR.length()
                    + simiarityTypesNamesMaxLength) * similarityTypesNames.size());
            for (String similarityTypeName : similarityTypesNames) {
                csvLine.append(CSV_TRIMMED_SEPARATOR);
                csvLine.append(escapeCsv(similarityTypeName));
            }
            writer.println(csvLine.toString());

            int i = 0;
            Set<Entry<T, Map<SimilarityTypes, Double>>> entries = similarities.entrySet();
            for (Entry<T, Map<SimilarityTypes, Double>> entry : entries) {

                Map<SimilarityTypes, Double> similarities1 = entry.getValue();

                csvLine = new StringBuilder(identifiersMaxLength + (CSV_TRIMMED_SEPARATOR.length()
                        + ZERO_TO_ONE_DECIMAL_MAX_CHARS) * similarityTypesNames.size());
                String preparedIdentifier = preparedIdentifiers.get(i);
                csvLine.append(escapeCsv(preparedIdentifier));
                for (SimilarityTypes similarityType : SimilarityTypes.values()) {
                    Double similarity = null;
                    if (similarities1 != null) {
                        similarity = similarities1.get(similarityType);
                    }
                    csvLine.append(CSV_TRIMMED_SEPARATOR);
                    csvLine.append(formatDecimal(similarity));
                }
                writer.println(csvLine.toString());

                if (i == rowsLimit - 1) {
                    break;
                }

                i++;

            }

        }

    }

    /**
     * Prints a table showing the similarity between all the hashes in a map of identified Uniform
     * Fuzzy Hashes.
     * 
     * @param <T> Identifiers type.
     * @param similarities Map of identified similarities (As it is returned from the method
     *        computeAllHashesSimilarities).
     * @param truncateIdentifiers Introduce a number larger than 0 to truncate the identifiers to a
     *        maximum length.
     * @param markAbove Mark all similarities above or equal to this threshold with a color.
     *        Introduce a negative number to not mark any similarity.
     * @param markBelow Mark all similarities below this threshold with a color. Introduce a
     *        negative number to not mark any similarity.
     */
    public static <T> void printAllHashesSimilaritiesTable(
            Map<T, Map<T, Double>> similarities,
            int truncateIdentifiers,
            double markAbove,
            double markBelow) {

        // Parameters check.
        if (similarities == null) {
            throw new NullPointerException("Map of similarities is null.");
        }

        if (similarities.isEmpty()) {
            return;
        }

        // Identifiers.
        Set<T> identifiers = similarities.keySet();
        List<String> preparedIdentifiers = prepareIdentifiers(identifiers, truncateIdentifiers);
        int identifiersMaxLength = maxLength(preparedIdentifiers);

        // Column size.
        int firstColumnSize = getColumnSize(identifiersMaxLength);
        int columnSize = getColumnSize(ZERO_TO_ONE_DECIMAL_MAX_CHARS, identifiersMaxLength);

        // Table print.
        final PrintStream printStream;

        if (markAbove >= 0 || markBelow >= 0) {
            printStream = AnsiConsole.out;
        } else {
            printStream = System.out;
        }

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemInstall();
        }

        printStream.println();

        printFirstColumn("", firstColumnSize, printStream);
        for (String preparedIdentifier : preparedIdentifiers) {
            printColumn(preparedIdentifier, columnSize, printStream);
        }
        printStream.println();

        printFirstRowSeparator(
                firstColumnSize, columnSize, identifiers.size(), printStream);

        int i = 0;
        Set<Entry<T, Map<T, Double>>> entries = similarities.entrySet();
        for (Entry<T, Map<T, Double>> entry : entries) {

            Map<T, Double> similarities1 = entry.getValue();

            String preparedIdentifier = preparedIdentifiers.get(i);
            printFirstColumn(preparedIdentifier, firstColumnSize, printStream);
            for (T identifier1 : identifiers) {
                Double similarity = null;
                if (similarities1 != null) {
                    similarity = similarities1.get(identifier1);
                }
                printColumn(formatDecimal(similarity, markAbove, markBelow),
                        columnSize, printStream);
            }
            printStream.println();

            i++;

        }

        printStream.println();

        if (printStream == AnsiConsole.out) {
            AnsiConsole.systemUninstall();
        }

    }

    /**
     * Writes a table showing the similarity between all the hashes in a map of identified Uniform
     * Fuzzy Hashes into a CSV file, overwriting it.
     * 
     * @param <T> Identifiers type.
     * @param similarities Map of identified similarities (As it is returned from the method
     *        computeAllHashesSimilarities).
     * @param csvFile The file to save the CSV.
     * @throws IOException If an IOException occurs writing into the file.
     */
    public static <T> void saveAllHashesSimilaritiesAsCsv(
            Map<T, Map<T, Double>> similarities,
            File csvFile)
            throws IOException {

        // Parameters check.
        if (similarities == null) {
            throw new NullPointerException("Map of similarities is null.");
        }

        if (similarities.isEmpty()) {
            return;
        }

        if (csvFile == null) {
            throw new NullPointerException("CSV file is null.");
        }

        if (csvFile.exists() && !csvFile.isFile()) {
            throw new IllegalArgumentException(String.format(
                    "%s is not a file.",
                    csvFile.getName()));
        }

        // Identifiers.
        Set<T> identifiers = similarities.keySet();
        List<String> preparedIdentifiers = prepareIdentifiers(identifiers, -1);
        int identifiersMaxLength = maxLength(preparedIdentifiers);

        // Generate CSV.
        try (PrintWriter writer = new PrintWriter(new FileWriterWithEncoding(
                csvFile, FILES_ENCODING, false))) {

            StringBuilder csvLine = null;

            csvLine = new StringBuilder((CSV_TRIMMED_SEPARATOR.length()
                    + identifiersMaxLength) * preparedIdentifiers.size());
            for (String preparedIdentifier : preparedIdentifiers) {
                csvLine.append(CSV_TRIMMED_SEPARATOR);
                csvLine.append(escapeCsv(preparedIdentifier));
            }
            writer.println(csvLine.toString());

            int i = 0;
            Set<Entry<T, Map<T, Double>>> entries = similarities.entrySet();
            for (Entry<T, Map<T, Double>> entry : entries) {

                Map<T, Double> similarities1 = entry.getValue();

                csvLine = new StringBuilder(identifiersMaxLength + (CSV_TRIMMED_SEPARATOR.length()
                        + ZERO_TO_ONE_DECIMAL_MAX_CHARS) * preparedIdentifiers.size());
                String preparedIdentifier = preparedIdentifiers.get(i);
                csvLine.append(escapeCsv(preparedIdentifier));
                for (T identifier1 : identifiers) {
                    Double similarity = null;
                    if (similarities1 != null) {
                        similarity = similarities1.get(identifier1);
                    }
                    csvLine.append(CSV_TRIMMED_SEPARATOR);
                    csvLine.append(formatDecimal(similarity));
                }
                writer.println(csvLine.toString());

                i++;

            }

        }

    }

    /**
     * @param sizes Varargs of lengths of the strings which will be printed in the column.
     * @return The column size.
     */
    private static int getColumnSize(
            int... sizes) {

        int maxSize = 0;

        for (int size : sizes) {
            if (size > maxSize) {
                maxSize = size;
            }
        }

        return maxSize + TAB.length();

    }

    /**
     * Prints a string followed by an amount of spaces such that columnSize characters are printed.
     * 
     * @param text The string to print.
     * @param columnSize Amount of characters to print.
     * @param printStream Print stream that will be used to print.
     */
    private static void printColumn(
            String text,
            int columnSize,
            PrintStream printStream) {

        int textLength = 0;
        if (printStream == AnsiConsole.out) {
            textLength = AnsiCodeColors.remove(text).length();
        } else {
            textLength = text.length();
        }

        printStream.print(text + spaces(columnSize - textLength));

    }

    /**
     * Prints a string in a column and then the first column separator.
     * 
     * @param text The string to print.
     * @param columnSize Column size.
     * @param printStream Print stream that will be used to print.
     * 
     */
    private static void printFirstColumn(
            String text,
            int columnSize,
            PrintStream printStream) {

        printColumn(text, columnSize, printStream);
        printStream.print('|' + TAB);

    }

    /**
     * Prints the first row separator.
     * 
     * @param firstColumnSize First column size.
     * @param columnSize Other columns size.
     * @param nColumns Number of columns
     * @param printStream Print stream that will be used to print.
     */
    private static void printFirstRowSeparator(
            int firstColumnSize,
            int columnSize,
            int nColumns,
            PrintStream printStream) {

        printStream.println(hyphens(firstColumnSize) + '+'
                + hyphens(TAB.length() + columnSize * nColumns));

    }

}
