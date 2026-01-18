package hw0.socket_time;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Server {
    public static void main(String[] args) {
        int port = 10000;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is starting. Wait connection...");

            // Wait client
            try (Socket clientSocket = serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                System.out.println("Client is connected: " + clientSocket.getInetAddress());

                String inputLine;
                // Read messages from client in cycle
                while ((inputLine = in.readLine()) != null) {
                    System.out.println("Received from client: " + inputLine);

                    // Format current date and time
                    String currentTime = LocalDateTime.now()
                            .format(DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss"));

                    // Send response
                    out.println(currentTime);
                }
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }
}
