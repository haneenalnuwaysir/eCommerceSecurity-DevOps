package com.example.demo.Security;

public class SecurityConstants {
    public static final String SECRET = "oursecretkey";
    public static final long EXPIRATION_TIME = 864_000_000; //10days 864000=10*24*60*60s
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/api/user/create";
}