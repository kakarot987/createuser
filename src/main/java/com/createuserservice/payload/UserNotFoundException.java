package com.createuserservice.payload;

public class UserNotFoundException extends Throwable {
    private String message;

    public UserNotFoundException(String message) {
        this.message = message;
    }
}
