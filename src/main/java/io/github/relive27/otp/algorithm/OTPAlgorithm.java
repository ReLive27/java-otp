package io.github.relive27.otp.algorithm;

public enum OTPAlgorithm {

    SHA1("HmacSHA1", "SHA1"),
    SHA256("HmacSHA256", "SHA256"),
    SHA512("HmacSHA512", "SHA512");

    private final String algorithm;
    private final String friendlyName;

    OTPAlgorithm(String algorithm, String friendlyName) {
        this.algorithm = algorithm;
        this.friendlyName = friendlyName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getFriendlyName() {
        return friendlyName;
    }
}
