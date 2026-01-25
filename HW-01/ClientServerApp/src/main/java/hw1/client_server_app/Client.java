package hw1.client_server_app;

import java.io.*;
import java.net.Socket;
import java.util.Random;

public class Client {
    public static void main(String[] args) {
        if (args.length < 5) {
            System.err.println("Need: <IP> <port> <N> <M> <Q>");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        int N = Integer.parseInt(args[2]);
        int M = Integer.parseInt(args[3]);
        int Q = Integer.parseInt(args[4]);

        boolean tcpNoDelay = true;
        if (args.length >= 6) {
            tcpNoDelay = Boolean.parseBoolean(args[5]);
        }
        String outFile = null;
        if (args.length >= 7) {
            outFile = args[6];
        }

        System.out.printf("Client: %s:%d, N=%d, M=%d, Q=%d, tcpNoDelay=%b%n", host, port, N, M, Q, tcpNoDelay);
        try (Socket socket = new Socket(host, port)) {
            socket.setTcpNoDelay(tcpNoDelay);

            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                Random rnd = new Random();
                StringBuilder csv = new StringBuilder();
                csv.append("bytes,avg_millis\n");

                for (int K = 0; K < M; K++) {
                    int len = N * K + 8;
                    long sum = 0L;

                    for (int q = 0; q < Q; q++) {
                        byte[] payload = new byte[len];
                        rnd.nextBytes(payload);

                        long t0 = System.currentTimeMillis();

                        dos.writeInt(len);
                        if (len > 0) {
                            dos.write(payload);
                        }
                        dos.flush();

                        in.readLine();

                        long t1 = System.currentTimeMillis();

                        long delta = t1 - t0;
                        sum += delta;
                    }

                    double avg = (double) sum / Q;
                    csv.append(len).append(",").append(String.format("%.4f", avg)).append("\n");

                    if (K % Math.max(1, M / 10) == 0) {
                        System.out.printf("Progress: K=%d/%d\tlen=%d\tavg=%.4fms%n", K, M-1, len, avg);
                    }
                }

                if (outFile != null) {
                    try (FileWriter fw = new FileWriter(outFile)) {
                        fw.write(csv.toString());
                        System.out.println("Results written to " + outFile);
                    }
                } else {
                    System.out.printf("CSV results: %s%n", csv);
                }
            }
        } catch (IOException e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }
}
