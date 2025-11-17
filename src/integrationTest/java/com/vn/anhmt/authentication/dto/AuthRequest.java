package com.vn.anhmt.authentication.dto;

public class AuthRequest {
    private String grantType;
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String scope;
    private String state;
    private String code;

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {}
}
