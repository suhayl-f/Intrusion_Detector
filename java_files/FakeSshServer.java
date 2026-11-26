import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class FakeSshServer {
    private static final int PORT = 2222;
    private static final String LOG_FILE = "logs/auth.log";

    public static void main(String[] args) {
        System.out.println("Starting Fake SSH Honeypot on port " + PORT + "...");
        System.out.println("Logging connection attempts to: " + LOG_FILE);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                // Handle each incoming connection on a separate thread
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket) {
        // Extract the caller's real IP address
        String clientIp = socket.getInetAddress().getHostAddress();
        if (clientIp.startsWith("::ffff:")) {
            clientIp = clientIp.substring(7); // Clean IPv4-mapped IPv6 prefix if present
        }
        int clientPort = socket.getPort();

        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            out.println("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
            out.print("login as: ");
            out.flush();

            String username = in.readLine();
            if (username == null || username.isBlank()) {
                username = "unknown";
            }
            username = username.trim().replaceAll("\\s+", "_");

            // Give your friend 6 password tries so they can trigger your 5-attempt Brute-Force rule
            for (int attempt = 1; attempt <= 6; attempt++) {
                out.print(username + "@prod-web-01's password: ");
                out.flush();

                String password = in.readLine();
                if (password == null) break; // Friend disconnected

                logFailedAttempt(username, clientIp, clientPort);
                out.println("Permission denied, please try again.");
            }
        } catch (IOException e) {
            // Client disconnected abruptly
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
        }
    }

    private static synchronized void logFailedAttempt(String user, String ip, int port) {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH);
        String timestamp = LocalDateTime.now().format(fmt);

        String logLine = String.format(
            "%s prod-web-01 sshd: Failed password for %s from %s port %d ssh2%n",
            timestamp, user, ip, port
        );

        try {
            Path path = Path.of(LOG_FILE);
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, logLine, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.out.print("Logged: " + logLine);
        } catch (IOException e) {
            System.err.println("Failed to write to auth.log: " + e.getMessage());
        }
    }
}
