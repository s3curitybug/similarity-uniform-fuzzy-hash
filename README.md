# Similarity Uniform Fuzzy Hash

Similarity Uniform Fuzzy Hash is a tool that allows to accurately and efficiently compute the similarity between two files (or sets of bytes) as a 0 to 1 score.

For that purpose, it first computes for each file a Context Triggered Piecewise Hash (CTPH), also known as fuzzy hash, and then compares the hashes.

Both, the hash computation and the hashes comparison algorithms present linear complexity, the former with respect to the file size (or the amount of bytes), and the latter with respect to the hashes length, which is proportional to the files size divided by a choosable factor. This fact makes the tool very efficient and ideal for clustering (finding the most or least similar files to a given one between a set or database of many files). In fact, there is no need to store the files, storing the hashes is enough.

The tool provides methods to:

  * Compute a file hash.

  * Compute the hashes of a set of files.

  * Compute the similarity between two hashes.

  * Compute and show in a table the similarity between a hash and a set of hashes, ordering them by similarity to the first one.

  * Compute and show in a table the similarity between all the hashes in a set.

  * Save and load hashes into / from a text file.

  * Visually compare two files or hashes, identifying their common parts.


# The Algorithm

The hash computation algorithm divides the file in blocks. The location of the divisions depends on the file contents. Thus, the blocks size is not constant, but the mean block size is chosen by the user through a parameter called "factor". So the file is divided in blocks of size around factor. Then, each block is converted into two hexadecimal numbers, the first one representing its content and the second one representing its size. Finally, the hash is written as the factor followed by each block.

<img src="https://cloud.githubusercontent.com/assets/26045270/25785171/691da24a-337a-11e7-901d-bb81951e5674.png" width=500>

This way, two files sharing some content would produce two hashes that share some blocks. The comparison algorithm finds the blocks of the first hash which are present in the second one (independently on their position), and returns a 0 to 1 similarity score based on the sum of their size, divided by the file total size, which is very accurate.

Note that the similarity score between File 1 and File 2 indicates the proportion of content of File 1 which is present in File 2. This is different to the similarity score between File 2 and File 1, which indicates the proportion of content of File 2 which is present in File 1. For files with similar size, both scores will be close. However, comparing a small file which is part of a big file to that big file would return a high score between the small file and the big one, but a low score between the big file and the small one. This means that the algorithm is able to detect small files inside big ones. For instance, it can detect images inside documents, and malwares inside executables. The tool also provides methods to compute the maximum, minimum, arithmetic mean and geometric mean between the two similarity scores of two files.

<img src="https://cloud.githubusercontent.com/assets/26045270/25785258/a4dfc31a-337c-11e7-9fda-469190a20158.png" width=500>

Also note that the factor must be chosen carefully. The factor indicates the mean block size, in other words, the mean amount of bytes that must appear consecutively in both files such that some similarity is added to the score. This means that choosing too small factors would divide files in too small blocks, which may lead to similarities higher than expected and false possitives in similarity detections, while choosing too big factors would divide files in too big blocks, which may cause similarities lower than expected and false negatives.

Additionally, the hash length (which depends on the amount of blocks) is proportional to the file size divided by the factor. This means that big files and small factors produce large hashes (high amount of blocks), while small files and big factors produce small hashes (low amount of blocks). Consequently, it is recommended using a big factor when comparing big files, and small factor when comparing small ones. However, two hashes can only be compared if they were computed with the same factor. This means that, when comparing small files to big ones, a small factor must be used.

Due to the hash computation algorithm nature, factor must always be an odd number and larger than 2.
