package io.github.relive27.otp.exception;


/**
 * OTP 生成过程中的异常类，如密钥无效、算法不支持等。
 *
 * @author: ReLive27
 * @date: 2024/11/7 22:18
 */
public class OTPGenerationException extends RuntimeException {

    /**
     * 使用消息构造异常。
     *
     * @param message 异常描述信息
     */
    public OTPGenerationException(String message) {
        super(message);
    }

    /**
     * 使用消息和根本异常构造。
     *
     * @param message 异常描述信息
     * @param cause   原始异常
     */
    public OTPGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}

