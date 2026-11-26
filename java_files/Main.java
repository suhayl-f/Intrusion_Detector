import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class Main {
    public static void main(String[] args) {
        // Accept CLI arguments: java [LogFilePath] [outputJsonPath]
        String logPath = args.length > 0 ? args[0] : "logs/auth.log";
        String outputJsonPath = args.length > 1 ? args[1] : "logs/alerts.json";

        File logFile = new File(logPath);
        if (!logFile.exists()) {
            System.err.println("Error: Log file not found at: " + logFile.getAbsolutePath());
            System.err.println("Usage: java Main [path/to/auth.log] [path/to/alerts.json");
            System.exit(1);
        }

        ThreatDetector detector = new ThreatDetector(outputJsonPath);

        System.out.println("Starting Real-Time Log Intrusion Detection on: " + logFile.getName());
        System.out.println("Monitoring File: " + logFile.getAbsolutePath());
        System.out.println("Exporting Alerts: " + outputJsonPath);
        System.out.println("Press Ctrl+C to stop monitoring...\n");

        long filePointer = 0;

        while (true) {
            try {
                long fileLength = logFile.length();

                // Handle log rotation or file truncation if the file shrinks
                if (fileLength < filePointer) {
                    filePointer = 0;
                }

                if (fileLength > filePointer) {
                    try (RandomAccessFile raf = new RandomAccessFile(logFile, "r")) {
                        raf.seek(filePointer);
                        String line;
                        while ((line = raf.readLine()) != null) {
                            LogParser.parse(line).ifPresent(detector::analyze);
                        }
                        filePointer = raf.getFilePointer();
                    }
                }

                Thread.sleep(500); // Poll for new log entries every 0.5 seconds
            } catch (IOException e) {
                System.err.println("Error reading log file: " + e.getMessage());
            } catch (InterruptedException e) {
                System.out.println("\nMonitoring stopped.");
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
}
