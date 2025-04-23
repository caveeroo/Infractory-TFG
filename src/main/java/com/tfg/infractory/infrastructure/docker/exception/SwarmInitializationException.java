package com.tfg.infractory.infrastructure.docker.exception;

/**
 * Exception thrown when Docker Swarm initialization fails.
 */
public class SwarmInitializationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new SwarmInitializationException with the specified detail
     * message.
     * 
     * @param message The detail message
     */
    public SwarmInitializationException(String message) {
        super(message);
    }

    /**
     * Constructs a new SwarmInitializationException with the specified detail
     * message and cause.
     * 
     * @param message The detail message
     * @param cause   The cause
     */
    public SwarmInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}