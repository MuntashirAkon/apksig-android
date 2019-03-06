package com.android.apksig.internal.apk;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ApkSigningBlockUtilsTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private static int BASE = 255; // Intentionally not power of 2 to test properly

    @Test
    public void testMultithreadVersionMatchesSinglethreaded() throws Exception {
        Set<ContentDigestAlgorithm> algos = new HashSet<>(Arrays
                .asList(ContentDigestAlgorithm.CHUNKED_SHA512));
        Map<ContentDigestAlgorithm, byte[]> outputContentDigests = new HashMap<>();
        Map<ContentDigestAlgorithm, byte[]> outputContentDigestsMultithread = new HashMap<>();

        byte[] part1 = new byte[80 * 1024 * 1024 + 12345];
        for (int i = 0; i < part1.length; ++i) {
            part1[i] = (byte)(i % BASE);
        }

        File dataFile = temporaryFolder.newFile("fake.apk");

        try (FileOutputStream fos = new FileOutputStream(dataFile)) {
            fos.write(part1);
        }
        RandomAccessFile raf = new RandomAccessFile(dataFile, "r");

        byte[] part2 = new byte[1_500_000];
        for (int i = 0; i < part2.length; ++i) {
            part2[i] = (byte)(i % BASE);
        }
        byte[] part3 = new byte[30_000];
        for (int i = 0; i < part3.length; ++i) {
            part3[i] = (byte)(i % BASE);
        }

        DataSource[] dataSource = {
                DataSources.asDataSource(raf),
                DataSources.asDataSource(ByteBuffer.wrap(part2)),
                DataSources.asDataSource(ByteBuffer.wrap(part3)),
        };

        ApkSigningBlockUtils.computeOneMbChunkContentDigests(
                algos, dataSource, outputContentDigests);

        ApkSigningBlockUtils.computeOneMbChunkContentDigestsMultithread(
                algos, dataSource, outputContentDigestsMultithread);

        assertEquals(outputContentDigestsMultithread.keySet(), outputContentDigests.keySet());
        for (ContentDigestAlgorithm algo : outputContentDigests.keySet()) {
            byte[] digest1 = outputContentDigestsMultithread.get(algo);
            byte[] digest2 = outputContentDigests.get(algo);
            assertArrayEquals(digest1, digest2);
        }
    }
}
