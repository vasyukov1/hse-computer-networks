package hw1.client_server_app;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class Server {
    public static void main(String[] args) {
        int port = 10000;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }

        System.out.println("Server is starting on port " + port);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Wait connection...");

            try (Socket clientSocket = serverSocket.accept();
                 DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                System.out.println("Client is connected: " + clientSocket.getInetAddress());
                DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

                while (true) {
                    int len;
                    try {
                        len = in.readInt();
                    } catch (IOException e) {
                        System.out.println("Client read if failed: " + e.getMessage());
                        break;
                    }

                    if (len < 0) {
                        System.out.println("Length is negative");
                        break;
                    }

                    byte[] payload = new byte[len];
                    in.readFully(payload);

                    System.out.println("Received payload length: " + len);

                    String now = ZonedDateTime.now(ZoneId.systemDefault()).format(fmt);
                    out.println(now);
                }
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }
}

