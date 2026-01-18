package hw0.socket_time;

import java.io.*;
import java.net.Socket;
import java.util.UUID;

public class Client {
    public static void main(String[] args) {
        String host = "127.0.0.1";
        int port = 10000;

        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            System.out.println("Connected to server " + host + ":" + port);

            while (true) {
                // Generate random line
                String message = "Ping-" + UUID.randomUUID().toString().substring(0, 4);

                // Send message to server
                out.println(message);

                // Read response
                String response = in.readLine();
                System.out.println("Server response: " + response);

                // Pause
                Thread.sleep(1000);
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }
}

