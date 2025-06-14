package io.github.relive27.otp.algorithm;

import io.github.relive27.otp.exception.OTPGenerationException;
import org.apache.commons.codec.binary.Base32;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * {@code ShaAlgoFunc} 实现了 {@link AlgoFunc} 接口，负责使用指定的 HMAC 算法（如 HmacSHA1、HmacSHA256、HmacSHA512）
 * 生成一次性密码（OTP）所需的哈希值。
 *
 * <p>该类主要用于 TOTP/HOTP 的哈希计算阶段，输出为 HMAC 的结果字节数组，供动态截断生成最终的 OTP。</p>
 *
 * @author: ReLive27
 * @date: 2025/5/28 22:12
 */
public class ShaAlgoFunc implements AlgoFunc {

    /**
     * HMAC 算法枚举，如 HmacSHA1、HmacSHA256、HmacSHA512。
     */
    private final OTPAlgorithm algorithm;

    /**
     * 构造方法，指定要使用的 HMAC 算法。
     *
     * @param algorithm 使用的哈希算法
     */
    public ShaAlgoFunc(OTPAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * 根据密钥、计数因子生成 OTP 哈希。
     *
     * @param secret    Base32 编码的密钥
     * @param factor    时间步（TOTP）或计数器值（HOTP）
     * @param challenge 可选参数（当前未使用，可用于扩展）
     * @return 哈希字节数组，用于后续 OTP 动态截断处理
     * @throws OTPGenerationException 当密钥格式错误或算法不可用时抛出
     */
    @Override
    public byte[] compute(String secret, long factor, @Nullable String challenge) throws OTPGenerationException {
        try {
            return generateHash(secret, factor);
        } catch (InvalidKeyException e) {
            throw new OTPGenerationException("Invalid secret key: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new OTPGenerationException("Unsupported HMAC algorithm: " + algorithm.getAlgorithm(), e);
        }
    }

    /**
     * 生成 HMAC 哈希值。
     *
     * @param key     Base32 编码的密钥
     * @param counter 计数器或时间步因子
     * @return HMAC 哈希值
     * @throws InvalidKeyException      如果密钥格式错误
     * @throws NoSuchAlgorithmException 如果指定的算法不可用
     */
    private byte[] generateHash(String key, long counter) throws InvalidKeyException, NoSuchAlgorithmException {
        // 将 counter 转换为 8 字节数组（大端序）
        byte[] data = new byte[8];
        long value = counter;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        // 解码 Base32 密钥
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(key);

        // 创建 HMAC 签名密钥
        SecretKeySpec signKey = new SecretKeySpec(decodedKey, algorithm.getAlgorithm());

        // 计算 HMAC 哈希
        Mac mac = Mac.getInstance(algorithm.getAlgorithm());
        mac.init(signKey);
        return mac.doFinal(data);
    }
}

