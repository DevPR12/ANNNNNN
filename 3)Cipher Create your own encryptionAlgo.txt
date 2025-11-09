// //Design and Implement your own encryption/ decryption algorithm using any programming language
// import java.util.Scanner;

// class CustomCipher {

//     // Encrypt function
//     public static String encrypt(String text, String password) {
//         StringBuilder encrypted = new StringBuilder();
//         int pwdLen = password.length();

//         for (int i = 0; i < text.length(); i++) {
//             char plainChar = text.charAt(i);
//             char pwdChar = password.charAt(i % pwdLen);

//             // custom rule: add + XOR with password length
//             int encryptedVal = (plainChar + pwdChar) ^ pwdLen;
//             encrypted.append((char) encryptedVal);
//         }
//         return encrypted.toString();
//     }

//     // Decrypt function
//     public static String decrypt(String text, String password) {
//         StringBuilder decrypted = new StringBuilder();
//         int pwdLen = password.length();

//         for (int i = 0; i < text.length(); i++) {
//             char encChar = text.charAt(i);
//             char pwdChar = password.charAt(i % pwdLen);

//             // reverse rule: XOR then subtract
//             int decryptedVal = (encChar ^ pwdLen) - pwdChar;
//             decrypted.append((char) decryptedVal);
//         }
//         return decrypted.toString();
//     }

//     // Main
//     public static void main(String[] args) {
//         Scanner sc = new Scanner(System.in);

//         // input
//         System.out.print("Enter message: ");
//         String message = sc.nextLine();

//         System.out.print("Enter password (key): ");
//         String password = sc.nextLine();

//         // encryption
//         String encrypted = encrypt(message, password);
//         System.out.println("Encrypted Text: " + encrypted);

//         // decryption
//         String decrypted = decrypt(encrypted, password);
//         System.out.println("Decrypted Text: " + decrypted);

//         sc.close();
//     }
// }


// // Your custom algorithm is a simple character-level transformation using:

// // Addition (+)

// // XOR (^) with password length

// // Decryption reverses it by XOR and subtraction.

// // 2️⃣ Steps of Your Algorithm

// // Encryption:
// // Take each character of the plaintext.
// // Take the corresponding character from the password (repeat if password shorter than text).

// // Add the ASCII value of password char to plaintext char.

// // XOR the result with the password length.

// // Convert back to character → this is your encrypted character.

// // Decryption:

// // Take each encrypted character.

// // XOR with password length.

// // Subtract the password character’s ASCII.

// // Convert back to character → original text.




// // Encryption Step

// // Your algorithm does for each character:

// // Take plaintext char → e.g., P (ASCII 80)

// // Take password char → 3 (ASCII 51)

// // Add them → 80 + 51 = 131

// // XOR with password length → password length = 1 → 131 ^ 1 = 130

// // Convert back to char → ASCII 130 → ? (non-printable/special character)

// // Repeat for all characters:

// // C (67) + 3 (51) = 118 ^ 1 = 119 → 'w'

// // C → 'w'

// // O (79) + 3 (51) = 130 ^ 1 = 131 → '?'

// // E (69) + 3 (51) = 120 ^ 1 = 121 → 'y'


import java.util.Scanner;

public class Ass_3 {

    // Encrypt function
    public static String encrypt(String text, String password) {
        StringBuilder encrypted = new StringBuilder();
        int pwdLen = password.length();

        for (int i = 0; i < text.length(); i++) {
            char plainChar = text.charAt(i);
            char pwdChar = password.charAt(i % pwdLen);

            // Custom rule: add + XOR with password length
            int encryptedVal = (plainChar + pwdChar) ^ pwdLen;
            encrypted.append((char) encryptedVal);
        }
        return encrypted.toString();
    }

    // Decrypt function
    public static String decrypt(String text, String password) {
        StringBuilder decrypted = new StringBuilder();
        int pwdLen = password.length();

        for (int i = 0; i < text.length(); i++) {
            char encChar = text.charAt(i);
            char pwdChar = password.charAt(i % pwdLen);

            // Reverse rule: XOR then subtract
            int decryptedVal = (encChar ^ pwdLen) - pwdChar;
            decrypted.append((char) decryptedVal);
        }
        return decrypted.toString();
    }

    // Main method
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        // Input message
        System.out.print("Enter message: ");
        String message = sc.nextLine();

        // Input password (key)
        System.out.print("Enter password (key): ");
        String password = sc.nextLine();

        // Encryption
        String encrypted = encrypt(message, password);
        System.out.println("Encrypted Text: " + encrypted);

        // Decryption
        String decrypted = decrypt(encrypted, password);
        System.out.println("Decrypted Text: " + decrypted);

        sc.close();
    }
}
