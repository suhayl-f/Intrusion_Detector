import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import java.util.*;

public class Main {
    public static void main(String args[]) {
        Path logPath = Path.of("logs/auth.log");
        ThreatDetector detector = new ThreatDetector();

        System.out.println("Starting Log Intrusion Detection...");
        try (Stream<String> lines = Files.lines(logPath)) {
            lines.map(LogParser::parse).flatMap(Optional::stream).forEach(detector::analyze);
        } catch (IOException e) {
            System.err.println("Error reading log file: " + e.getMessage());
        }
    }
}
