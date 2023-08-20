package com.example.sstest.exception;

public class UnAuthorizedException extends RuntimeException {
    public static final String DEFAULT_MESSAGE = "계정 권한이 유효하지 않습니다.\n다시 로그인을 해주세요.";

    public UnAuthorizedException() {
        super(DEFAULT_MESSAGE);
    }

    public UnAuthorizedException(String msg) {
        super(msg);
    }

}