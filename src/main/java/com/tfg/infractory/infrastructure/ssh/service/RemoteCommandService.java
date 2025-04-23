package com.tfg.infractory.infrastructure.ssh.service;

import com.tfg.infractory.infrastructure.secrets.model.Secret;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.scp.client.ScpClient;
import org.apache.sshd.scp.client.ScpClientCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.security.SecurityUtils;

@Service
public class RemoteCommandService {

    private static final Logger logger = LoggerFactory.getLogger(RemoteCommandService.class);
    private static final int MAX_RETRIES = 7;
    private static final long RETRY_INTERVAL_MS = 15000;

    @Autowired
    private SecretsService secretsService;

    public String executeCommand(String host, String user, String privateKeySecretName, String command,
            long timeoutSeconds) {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        Secret privateKeySecret = secretsService.getSecretByName(privateKeySecretName)
                .orElseThrow(() -> new RuntimeException("SSH Private Key Secret not found: " + privateKeySecretName));
        String decryptedPrivateKey = privateKeySecret.getContent();

        try (ByteArrayInputStream privateKeyStream = new ByteArrayInputStream(
                decryptedPrivateKey.getBytes(StandardCharsets.UTF_8))) {
            ConnectFuture connectFuture = null;
            ClientSession session = null;
            int retries = 0;

            while (retries < MAX_RETRIES) {
                try {
                    logger.debug("Attempting SSH connection ({}/{}) to {}@{}...", retries + 1, MAX_RETRIES, user, host);
                    connectFuture = client.connect(user, host, 22);
                    connectFuture.await(15, TimeUnit.SECONDS);
                    session = connectFuture.getSession();
                    if (session != null) {
                        logger.debug("SSH connection successful.");
                        break;
                    }
                } catch (Exception e) {
                    logger.warn("SSH connection attempt {}/{} failed: {}", retries + 1, MAX_RETRIES, e.getMessage());
                    if (session != null) {
                        session.close(true);
                        session = null;
                    }
                    if (retries + 1 >= MAX_RETRIES) {
                        logger.error("Max SSH connection retries reached for {}@{}", user, host);
                        throw new RuntimeException(
                                "Failed to connect to " + host + " after " + MAX_RETRIES + " attempts", e);
                    }
                    Thread.sleep(RETRY_INTERVAL_MS);
                } finally {
                    retries++;
                }
            }

            if (session == null) {
                throw new RuntimeException("Failed to establish SSH session with " + host);
            }

            try (ClientSession verifiedSession = session) {
                KeyPair keyPair = SecurityUtils.loadKeyPairIdentities(
                        verifiedSession,
                        null,
                        privateKeyStream,
                        null).iterator().next();
                verifiedSession.addPublicKeyIdentity(keyPair);
                verifiedSession.auth().verify(10, TimeUnit.SECONDS);
                logger.debug("SSH authentication successful for {}@{}", user, host);

                StringBuilder outputBuilder = new StringBuilder();
                try (ClientChannel channel = verifiedSession.createExecChannel(command)) {
                    channel.setOut(new OutputStream() {
                        @Override
                        public void write(int b) {
                            char c = (char) b;
                            outputBuilder.append(c);
                            System.out.print(c); // Print real-time output
                        }
                    });
                    channel.setErr(new OutputStream() {
                        @Override
                        public void write(int b) {
                            char c = (char) b;
                            outputBuilder.append(c);
                            System.err.print(c); // Print real-time error output
                        }
                    });
                    channel.open().verify(10, TimeUnit.SECONDS);

                    Set<ClientChannelEvent> events = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED),
                            TimeUnit.SECONDS.toMillis(timeoutSeconds));

                    if (events.contains(ClientChannelEvent.TIMEOUT)) {
                        throw new RuntimeException("Command execution timed out after " + timeoutSeconds + " seconds");
                    }

                    Integer exitStatusObj = channel.getExitStatus();
                    String response = outputBuilder.toString();

                    // Handle case where exit status can be null for some commands
                    if (exitStatusObj == null) {
                        logger.info("Command response (exit status unknown): {}", response);
                        // For commands that might not set exit status, assume success if output is
                        // present
                        // This happens particularly with kill commands that terminate the connection
                        if (command.contains("pkill") || command.contains("kill") || response.trim().isEmpty()) {
                            return response;
                        }
                        // For other commands, assume failure if exit status is null
                        throw new RuntimeException(
                                "Command execution failed with unknown exit status. Output: " + response);
                    }

                    int exitStatus = exitStatusObj;
                    logger.info("Command response (exit status {}): {}", exitStatus, response);

                    if (exitStatus != 0) {
                        throw new RuntimeException(
                                "Command execution failed with exit status " + exitStatus + ". Output: " + response);
                    }

                    return response;
                }
            }
        } catch (Exception e) {
            logger.error("Error executing remote command: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to execute remote command: " + e.getMessage(), e);
        } finally {
            client.stop();
        }
    }

    public void uploadFile(String host, String user, String privateKeySecretName, String remoteFilePath, byte[] content)
            throws IOException {
        uploadFile(host, 22, user, privateKeySecretName, remoteFilePath, content);
    }

    public void uploadFile(String host, int port, String user, String privateKeySecretName, String remoteFilePath,
            byte[] content)
            throws IOException {

        Secret privateKeySecret = secretsService.getSecretByName(privateKeySecretName)
                .orElseThrow(() -> new IOException("SSH Private Key Secret not found: " + privateKeySecretName));
        String decryptedPrivateKey = privateKeySecret.getContent();

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ByteArrayInputStream privateKeyStream = new ByteArrayInputStream(
                    decryptedPrivateKey.getBytes(StandardCharsets.UTF_8));
                    ClientSession session = client.connect(user, host, port)
                            .verify(10, TimeUnit.SECONDS)
                            .getSession()) {

                KeyPair keyPair = SecurityUtils.loadKeyPairIdentities(session, null, privateKeyStream, null)
                        .iterator().next();
                session.addPublicKeyIdentity(keyPair);
                session.auth().verify(10, TimeUnit.SECONDS);

                ScpClientCreator creator = ScpClientCreator.instance();
                ScpClient scpClient = creator.createScpClient(session);

                Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-r--r--");
                scpClient.upload(content, remoteFilePath, permissions, null);

                logger.info("Uploaded file to {}", remoteFilePath);
            } catch (Exception e) {
                logger.error("Error uploading file to {}", remoteFilePath, e);
                throw new IOException("Failed to upload file", e);
            }
        }
    }
}