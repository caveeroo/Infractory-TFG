package com.tfg.infractory.domain.exception;

public class InstanceNotFoundException extends Exception {
    public InstanceNotFoundException(String message) {
        super(message);
    }

    public InstanceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}