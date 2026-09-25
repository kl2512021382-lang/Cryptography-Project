import javax.crypto.SecretKey;

public class PerformanceTest
{
    // Create a string with exactly the required number of ASCII bytes
    public static String createTestData(int size)
    {
        StringBuilder data = new StringBuilder(size);

        for (int i = 0; i < size; i++)
        {
            data.append('A');
        }

        return data.toString();
    }

    public static void main(String[] args) throws Exception
    {
        // Generate one key for each algorithm
        int lfsrKey = LFSRcipher.generateKey();
        SecretKey aesKey = AEScrypto.generateKey();

        // Test sizes
        int[] sizes = {
            1024,          // 1 KB
            102400,        // 100 KB
            1048576        // 1 MB
        };

        String[] names = {
            "1 KB",
            "100 KB",
            "1 MB"
        };

        System.out.println("==========================================================");
        System.out.println("          CRYPTOGRAPHIC PERFORMANCE TEST");
        System.out.println("==========================================================");

        System.out.printf("%-10s %-15s %-15s %-15s %-15s%n",
                "Size",
                "LFSR Enc(ms)",
                "LFSR Dec(ms)",
                "AES Enc(ms)",
                "AES Dec(ms)");

        System.out.println("----------------------------------------------------------");

        for (int i = 0; i < sizes.length; i++)
        {
            int size = sizes[i];
            String testData = createTestData(size);

            // =========================
            // LFSR ENCRYPTION
            // =========================

            long startLfsrEnc = System.nanoTime();

            int[] lfsrCipher =
                    LFSRcipher.encrypt(testData, lfsrKey);

            long endLfsrEnc = System.nanoTime();

            double lfsrEncTime =
                    (endLfsrEnc - startLfsrEnc) / 1_000_000.0;


            // =========================
            // LFSR DECRYPTION
            // =========================

            long startLfsrDec = System.nanoTime();

            String lfsrRecovered =
                    LFSRcipher.decrypt(lfsrCipher, lfsrKey);

            long endLfsrDec = System.nanoTime();

            double lfsrDecTime =
                    (endLfsrDec - startLfsrDec) / 1_000_000.0;


            // =========================
            // AES ENCRYPTION
            // =========================

            long startAesEnc = System.nanoTime();

            String aesCipher =
                    AEScrypto.encrypt(testData, aesKey);

            long endAesEnc = System.nanoTime();

            double aesEncTime =
                    (endAesEnc - startAesEnc) / 1_000_000.0;


            // =========================
            // AES DECRYPTION
            // =========================

            long startAesDec = System.nanoTime();

            String aesRecovered =
                    AEScrypto.decrypt(aesCipher, aesKey);

            long endAesDec = System.nanoTime();

            double aesDecTime =
                    (endAesDec - startAesDec) / 1_000_000.0;


            // =========================
            // CORRECTNESS CHECK
            // =========================

            boolean lfsrCorrect =
                    testData.equals(lfsrRecovered);

            boolean aesCorrect =
                    testData.equals(aesRecovered);


            // =========================
            // DISPLAY RESULTS
            // =========================

            System.out.printf("%-10s %-15.3f %-15.3f %-15.3f %-15.3f%n",
                    names[i],
                    lfsrEncTime,
                    lfsrDecTime,
                    aesEncTime,
                    aesDecTime);

            System.out.println("   LFSR correct: " + lfsrCorrect);
            System.out.println("   AES correct : " + aesCorrect);
            System.out.println();
        }

        System.out.println("==========================================================");
        System.out.println("                    TEST COMPLETE");
        System.out.println("==========================================================");
    }
}