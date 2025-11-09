
// Aim: A message is to be transmitted using network resources from one machine to another calculate 
//and demonstrate the use of a Hash value equivalent to SHA-1. Develop a program in C++/Python/Java using Eclipse.



import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class ass_5{

    // Left rotate 32-bit value
    static int leftRotate(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    // Manual SHA-1 implementation (same as before)
    static String sha1(String msg) {
        byte[] message = msg.getBytes(StandardCharsets.UTF_8);
        int originalLength = message.length;

        int numBlocks = ((originalLength + 8) >>> 6) + 1; // number of 512-bit blocks
        int totalLen = numBlocks << 6;
        byte[] padded = new byte[totalLen];
        System.arraycopy(message, 0, padded, 0, originalLength);
        padded[originalLength] = (byte) 0x80;
        long bitLen = (long) originalLength * 8;
        for (int i = 0; i < 8; i++) {
            padded[totalLen - 1 - i] = (byte) (bitLen >>> (8 * i));
        }

        int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
        int[] w = new int[80];

        for (int i = 0; i < numBlocks; i++) {
            int index = i << 6;
            for (int j = 0; j < 16; j++) {
                w[j] = ((padded[index + j * 4] & 0xFF) << 24)
                        | ((padded[index + j * 4 + 1] & 0xFF) << 16)
                        | ((padded[index + j * 4 + 2] & 0xFF) << 8)
                        | (padded[index + j * 4 + 3] & 0xFF);
            }
            for (int j = 16; j < 80; j++)
                w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

            int a = h0, b = h1, c = h2, d = h3, e = h4;
            for (int j = 0; j < 80; j++) {
                int f, k;
                if (j < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
                else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
                else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6; }

                int temp = leftRotate(a, 5) + f + e + k + w[j];
                e = d; d = c; c = leftRotate(b, 30); b = a; a = temp;
            }

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }
        return String.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4);
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        // Sender side
        System.out.print("Sender: Enter message to send: ");
        String originalMessage = sc.nextLine();
        String sentHash = sha1(originalMessage);
        System.out.println("\nSender computes SHA-1 hash: " + sentHash);

        System.out.println("\n--- Sending message and hash over the network ---");

        // Simulate network: ask whether to tamper the message
        System.out.print("Simulate tampering of message in transit? (y/n) [n]: ");
        String tamper = sc.nextLine().trim();
        String receivedMessage;
        if (tamper.equalsIgnoreCase("y")) {
            System.out.print("Enter tampered message to simulate receiver getting: ");
            receivedMessage = sc.nextLine();
        } else {
            // message received as sent
            receivedMessage = originalMessage;
        }

        // Receiver side: receives message and the ORIGINAL hash (sentHash)
        System.out.println("\nReceiver got message: " + receivedMessage);
        System.out.println("Receiver got hash (from sender): " + sentHash);

        // Receiver recomputes hash from the received message (important!)
        String recomputed = sha1(receivedMessage);
        System.out.println("\nReceiver recomputes SHA-1 on received message: " + recomputed);

        // Compare recomputed hash with received (sent) hash
        if (recomputed.equalsIgnoreCase(sentHash)) {
            System.out.println("\nResult: HASH MATCH — message integrity verified.");
        } else {
            System.out.println("\nResult: HASH MISMATCH — message altered or corrupted!");
        }

        sc.close();
    }
}
