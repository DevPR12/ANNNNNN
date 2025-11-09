// Aim: Demonstrate how Diffie-Hellman key exchange works with Man-In-The-Middle attack.

// Theory:
// 1.	Importance of Diffie-Hellman key exchange algorithm
// 2.	Working of  Diffie-Hellman key exchange algorithm
// 3.	Example of algorithm.
// 4.	What is Man-In-The-Middle attack?


import java.math.BigInteger;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

class ass_4 {

    // Default (small) prime & generator for demonstration only
    static final BigInteger DEFAULT_P = BigInteger.valueOf(23);
    static final BigInteger DEFAULT_G = BigInteger.valueOf(5);
    static final Random RAND = new Random();

    // Generate a random private in range [1, P-2]
    static BigInteger randomPrivate(BigInteger P) {
        int max = P.intValue() - 2;
        if (max <= 1) return BigInteger.ONE;
        return BigInteger.valueOf(1 + RAND.nextInt(max));
    }

    // derive a simple 0-255 key from the BigInteger secret
    static int keyFromSecret(BigInteger secret) {
        return secret.mod(BigInteger.valueOf(256)).intValue();
    }

    // simple XOR encrypt -> Base64 (for printable)
    static String xorEncrypt(String plain, int key) {
        byte[] p = plain.getBytes();
        byte[] out = new byte[p.length];
        for (int i = 0; i < p.length; i++) out[i] = (byte) (p[i] ^ key);
        return Base64.getEncoder().encodeToString(out);
    }

    // XOR decrypt from Base64
    static String xorDecrypt(String cipherB64, int key) {
        byte[] c = Base64.getDecoder().decode(cipherB64);
        byte[] out = new byte[c.length];
        for (int i = 0; i < c.length; i++) out[i] = (byte) (c[i] ^ key);
        return new String(out);
    }

    static void sep() {
        System.out.println("--------------------------------------------------");
    }

    /**
     * Normal Diffie-Hellman flow (no MITM).
     * Generates Alice and Bob private/public keys, computes shared secret,
     * encrypts aliceMessage and shows Bob decrypting it.
     */
    static void runNormalDH(BigInteger P, BigInteger G, String aliceMessage) {
        System.out.println("Mode: Normal Diffie-Hellman (no MITM)");

        // Generate keys
        BigInteger alicePriv = randomPrivate(P);
        BigInteger alicePub  = G.modPow(alicePriv, P);

        BigInteger bobPriv = randomPrivate(P);
        BigInteger bobPub  = G.modPow(bobPriv, P);

        System.out.println("Alice: a=" + alicePriv + " A=" + alicePub);
        System.out.println("Bob:   b=" + bobPriv + " B=" + bobPub);

        // Compute shared secrets
        BigInteger aliceShared = bobPub.modPow(alicePriv, P); // g^(a*b)
        BigInteger bobShared   = alicePub.modPow(bobPriv, P); // g^(b*a)

        System.out.println("Alice computed shared secret: " + aliceShared);
        System.out.println("Bob   computed shared secret: " + bobShared);
        System.out.println("Secrets equal? " + aliceShared.equals(bobShared));
        sep();

        // Encrypt and exchange
        int key = keyFromSecret(aliceShared);
        String ct = xorEncrypt(aliceMessage, key);
        System.out.println("Alice sends (encrypted): " + ct);

        String bobReads = xorDecrypt(ct, keyFromSecret(bobShared));
        System.out.println("Bob decrypts and reads: " + bobReads);
    }

    /**
     * Diffie-Hellman with Man-in-the-Middle (Mallory).
     * Mallory creates two keypairs and intercepts Alice<->Bob exchange,
     * demonstrates Mallory reading and forwarding the message.
     */
    static void runMitmDH(BigInteger P, BigInteger G, String aliceMessage) {
        System.out.println("Mode: Diffie-Hellman with Man-in-the-Middle (Mallory)");

        // Real Alice and Bob generate their pairs
        BigInteger alicePriv = randomPrivate(P);
        BigInteger alicePub  = G.modPow(alicePriv, P);

        BigInteger bobPriv = randomPrivate(P);
        BigInteger bobPub  = G.modPow(bobPriv, P);

        System.out.println("Alice: a=" + alicePriv + " A=" + alicePub);
        System.out.println("Bob:   b=" + bobPriv + " B=" + bobPub);

        // Mallory generates two keypairs (one to talk to Alice, one to talk to Bob)
        BigInteger malloryPrivA = randomPrivate(P);
        BigInteger malloryPubA  = G.modPow(malloryPrivA, P);

        BigInteger malloryPrivB = randomPrivate(P);
        BigInteger malloryPubB  = G.modPow(malloryPrivB, P);

        System.out.println("Mallory: mA=" + malloryPrivA + " M_A=" + malloryPubA);
        System.out.println("Mallory: mB=" + malloryPrivB + " M_B=" + malloryPubB);
        sep();

        // Interception: Alice receives M_A, Bob receives M_B
        BigInteger aliceComputed = malloryPubA.modPow(alicePriv, P); // g^(a*mA)
        BigInteger bobComputed   = malloryPubB.modPow(bobPriv, P);   // g^(b*mB)

        // Mallory computes secrets with each party
        BigInteger malloryWithAlice = alicePub.modPow(malloryPrivA, P); // A^mA
        BigInteger malloryWithBob   = bobPub.modPow(malloryPrivB, P);   // B^mB

        System.out.println("Alice computed (using M_A): " + aliceComputed);
        System.out.println("Bob computed   (using M_B): " + bobComputed);
        System.out.println("Mallory<->Alice secret: " + malloryWithAlice);
        System.out.println("Mallory<->Bob   secret: " + malloryWithBob);

        System.out.println("Alice==Bob? " + aliceComputed.equals(bobComputed));
        System.out.println("Mallory matches Alice? " + malloryWithAlice.equals(aliceComputed));
        System.out.println("Mallory matches Bob?   " + malloryWithBob.equals(bobComputed));
        sep();

        // Message flow: Alice -> Bob (Mallory intercepts & forwards)
        int keyAliceSide = keyFromSecret(malloryWithAlice); // Mallory<->Alice key
        int keyBobSide   = keyFromSecret(malloryWithBob);   // Mallory<->Bob key

        String ct = xorEncrypt(aliceMessage, keyAliceSide);
        System.out.println("Alice sends (encrypted): " + ct);

        // Mallory intercepts and decrypts (using her key with Alice)
        String malloryReads = xorDecrypt(ct, keyAliceSide);
        System.out.println("Mallory intercepts and reads: " + malloryReads);

        // Mallory may modify the message here (demonstration uses same message)
        String modified = malloryReads; // change if you want to show tampering

        // Re-encrypt for Bob using Mallory<->Bob key
        String forward = xorEncrypt(modified, keyBobSide);
        System.out.println("Mallory forwards (encrypted to Bob): " + forward);

        // Bob decrypts using his computed secret (equals Mallory<->Bob)
        String bobReads = xorDecrypt(forward, keyFromSecret(bobComputed));
        System.out.println("Bob decrypts and reads: " + bobReads);
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Diffie-Hellman Demo (functions + switch)");
        System.out.println("Choose mode:");
        System.out.println("1) Normal DH (no MITM)");
        System.out.println("2) DH with Man-In-The-Middle (Mallory)");
        System.out.print("Enter choice (1 or 2): ");
        int choice = 1;
        try {
            choice = Integer.parseInt(sc.nextLine().trim());
        } catch (Exception e) {
            System.out.println("Invalid input, defaulting to 1");
        }

        // Choose whether to use default P/G or custom
        System.out.print("Use default P=23 G=5? (y/n) [y]: ");
        String useDefault = sc.nextLine().trim();
        BigInteger P = DEFAULT_P;
        BigInteger G = DEFAULT_G;
        if (useDefault.equalsIgnoreCase("n")) {
            try {
                System.out.print("Enter prime P (integer > 3): ");
                P = new BigInteger(sc.nextLine().trim());
                System.out.print("Enter generator G (integer > 1): ");
                G = new BigInteger(sc.nextLine().trim());
            } catch (Exception e) {
                System.out.println("Invalid input, falling back to defaults.");
                P = DEFAULT_P;
                G = DEFAULT_G;
            }
        }

        // Message input
        System.out.print("Enter message Alice will send to Bob (default: \"Hello Bob, from Alice.\"): ");
        String aliceMessage = sc.nextLine();
        if (aliceMessage.trim().isEmpty()) aliceMessage = "Hello Bob, from Alice.";

        sep();
        switch (choice) {
            case 1:
                runNormalDH(P, G, aliceMessage);
                break;
            case 2:
                runMitmDH(P, G, aliceMessage);
                break;
            default:
                System.out.println("Unknown choice. Exiting.");
        }

        sc.close();
    }
}
