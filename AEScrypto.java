import javax.crypto.Cipher;          // The engine that performs encryption and decryption
import javax.crypto.KeyGenerator;    // Builds a random AES key for user
import javax.crypto.SecretKey;       // A container that holds the key safely
import java.util.Base64;             // Turns binary data into readable text and back
import java.util.Scanner;            // Reads what the user types on the keyboard

public class AEScrypto
{
    // GENERATE A RANDOM AES KEY
    // This creates a fresh 128-bit AES key every time the program runs.
    // Internally, KeyGenerator asks the JCE (Java Cryptography Extension)
    // for an AES key then uses the system's secure random source to
    // fill it with unpredictable bytes.
    public static SecretKey generateKey() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // get an AES key builder
        keyGen.init(128);                                     // 128-bit key (16 bytes)
        return keyGen.generateKey();                          // produce the key
    }

    // ENCRYPT
    // Takes readable text and returns scrambled Base64 text.
    //
    // Internally, the Cipher object runs the full AES algorithm:
    //   - SubBytes:    each byte replaced via an S-box (non-linear step)
    //   - ShiftRows:   rows of the 4x4 state matrix are shifted
    //   - MixColumns:  columns are multiplied in GF(2^8)
    //   - AddRoundKey: XOR with a round key derived from our key
    // These four steps repeat for 10 rounds for a 128-bit key.
    public static String encrypt(String plaintext, SecretKey key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES");            // load AES engine
        cipher.init(Cipher.ENCRYPT_MODE, key);                // tell it: encrypt, use this key

        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes("UTF-8")); // run AES
        return Base64.getEncoder().encodeToString(cipherBytes);           // make it printable
    }

    // DECRYPT
    // Reverses the encryption. Uses the same AES engine but in
    // DECRYPT_MODE which runs the inverse transformations in reverse:
    //   - AddRoundKey (same as encryption, XOR is its own inverse)
    //   - InvMixColumns
    //   - InvShiftRows
    //   - InvSubBytes
    // The same key is used because AES is symmetric.
    public static String decrypt(String ciphertext, SecretKey key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES");            // load AES engine again
        cipher.init(Cipher.DECRYPT_MODE, key);                // tell it: decrypt, use same key

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext); // undo Base64
        byte[] plainBytes = cipher.doFinal(cipherBytes);              // run AES backwards
        return new String(plainBytes, "UTF-8");                       // back to text
    }

    // MAIN - communicate it to the user
    public static void main(String[] args) throws Exception
    {
        Scanner scanner = new Scanner(System.in);

        // Generate a random session key
        SecretKey key = generateKey();

        // Ask the user for the message to encrypt
        System.out.print("Enter plaintext: ");
        String plaintext = scanner.nextLine();
        // Encrypt the user's message
        String ciphertext = encrypt(plaintext, key);

        // Decrypt it back using the same key
        String recovered = decrypt(ciphertext, key);

        // Show results
        System.out.println();
        System.out.println("Plaintext   : " + plaintext);
        System.out.println("Ciphertext  : " + ciphertext);
        System.out.println("Decrypted   : " + recovered);
        System.out.println("Match       : " + plaintext.equals(recovered));

        scanner.close();
    }
}
