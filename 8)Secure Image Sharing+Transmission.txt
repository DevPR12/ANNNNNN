import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class ass_8 {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter image filename to encrypt/decrypt: ");
        String filename = sc.nextLine();

        System.out.print("Enter output filename: ");
        String outname = sc.nextLine();

        System.out.print("Enter single character key: ");
        char key = sc.next().charAt(0);

        try (FileInputStream input = new FileInputStream(filename);
             FileOutputStream output = new FileOutputStream(outname)) {

            int ch;
            while ((ch = input.read()) != -1) {
                ch = ch ^ key; // XOR encryption/decryption
                output.write(ch);
            }

            System.out.println("\nProcess completed successfully!");
            System.out.println("Output file: " + outname);
            System.out.println("(Run again with same key to decrypt the image)");

        } catch (IOException e) {
            System.out.println("Error: File not found or cannot be opened!");
        }

        sc.close();
    }
}
