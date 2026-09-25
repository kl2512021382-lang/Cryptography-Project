import java.security.SecureRandom;
import java.util.Scanner;

public class LFSRcipher
{

    private static final int LFSR_SIZE = 16;
    private static final int[] TAPS = {16, 14, 13, 11};

    public static int generateKey()
    {
        SecureRandom random = new SecureRandom();
        int key;
        do
        {
            key = random.nextInt(1 << LFSR_SIZE);
        } while (key == 0);
        return key;
    }

    public static int[] lfsrKeystream(int key, int[] taps, int length)
    {
        int state = key;
        int[] keystream = new int[length];

        for (int i = 0; i < length; i++)
        {
            int outBit = state & 1;
            keystream[i] = outBit;

            int feedback = 0;
            for (int t : taps) {
                feedback ^= (state >> (t - 1)) & 1;
            }

            state = (state >> 1) | (feedback << (LFSR_SIZE - 1));
        }

        return keystream;
    }

    public static int[] textToBits(String text)
    {
        int[] bits = new int[text.length() * 8];
        int idx = 0;
        for (char c : text.toCharArray())
        {
            for (int i = 7; i >= 0; i--)
            {
                bits[idx++] = (c >> i) & 1;
            }
        }
        return bits;
    }

    public static String bitsToText(int[] bits)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bits.length; i += 8)
        {
            int value = 0;
            for (int j = 0; j < 8; j++)
            {
                value = (value << 1) | bits[i + j];
            }
            sb.append((char) value);
        }
        return sb.toString();
    }

    public static int[] xorBits(int[] dataBits, int[] keystreamBits)
    {
        int[] result = new int[dataBits.length];
        for (int i = 0; i < dataBits.length; i++)
        {
            result[i] = dataBits[i] ^ keystreamBits[i];
        }
        return result;
    }

    public static int[] encrypt(String plaintext, int key)
    {
        int[] plainBits = textToBits(plaintext);
        int[] keystream = lfsrKeystream(key, TAPS, plainBits.length);
        return xorBits(plainBits, keystream);
    }

    public static String decrypt(int[] cipherBits, int key)
    {
        int[] keystream = lfsrKeystream(key, TAPS, cipherBits.length);
        int[] plainBits = xorBits(cipherBits, keystream);
        return bitsToText(plainBits);
    }

    public static void main(String[] args)
    {
        Scanner scanner = new Scanner(System.in);

        int key = generateKey();

        System.out.print("Enter plaintext: ");
        String plaintext = scanner.nextLine();

        int[] cipherBits = encrypt(plaintext, key);
        String recovered = decrypt(cipherBits, key);

        StringBuilder cipherStr = new StringBuilder();
        for (int b : cipherBits) cipherStr.append(b);

        System.out.println();
        System.out.println("Key (hex)   : 0x" + Integer.toHexString(key));
        System.out.println("Plaintext   : " + plaintext);
        System.out.println("Cipher bits : " + cipherStr);
        System.out.println("Decrypted   : " + recovered);
        System.out.println("Match       : " + plaintext.equals(recovered));

        scanner.close();
    }
}