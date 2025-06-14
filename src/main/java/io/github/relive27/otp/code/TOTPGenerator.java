package io.github.relive27.otp.code;

import io.github.relive27.otp.algorithm.AlgoFunc;
import io.github.relive27.otp.algorithm.OTPAlgorithm;
import io.github.relive27.otp.algorithm.ShaAlgoFunc;
import io.github.relive27.otp.exception.OTPGenerationException;

import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;


/**
 * 基于时间的一次性密码（TOTP）生成器实现。
 * <p>
 * 此类实现 {@link OTPGenerator} 接口，使用指定的 HMAC 算法（SHA-1、SHA-256、SHA-512）、
 * 时间步长和位数，生成符合 RFC 6238 的 TOTP 值。
 * </p>
 *
 * <p>默认配置为：HMAC-SHA1、30 秒时间步长、6 位 OTP。</p>
 *
 * @author: ReLive27
 * @date: 2025/5/28 22:10
 */
public class TOTPGenerator implements OTPGenerator {

    /**
     * 用于缓存和注册不同算法对应的哈希函数实现。
     */
    private static final Map<String, AlgoFunc> registry = new HashMap<>();

    static {
        // 注册支持的哈希算法
        registry.put(OTPAlgorithm.SHA1.getAlgorithm(), new ShaAlgoFunc(OTPAlgorithm.SHA1));
        registry.put(OTPAlgorithm.SHA256.getAlgorithm(), new ShaAlgoFunc(OTPAlgorithm.SHA256));
        registry.put(OTPAlgorithm.SHA512.getAlgorithm(), new ShaAlgoFunc(OTPAlgorithm.SHA512));
    }

    /**
     * 当前使用的 OTP 哈希算法（默认为 SHA1）。
     */
    private OTPAlgorithm algorithm;

    /**
     * 时间步长（单位：秒），默认值为 30 秒。
     */
    private int timePeriod;

    /**
     * OTP 位数
     */
    private int digits;

    /**
     * 使用默认参数构造 TOTP 生成器。
     * 默认使用：HMAC-SHA1、30 秒时间步长、6 位 OTP。
     */
    public TOTPGenerator() {
        this(OTPAlgorithm.SHA1, 30, 6);
    }

    /**
     * 构造自定义参数的 TOTP 生成器。
     *
     * @param algorithm  哈希算法（如 SHA1、SHA256）
     * @param timePeriod 时间步长（秒）
     * @param digits     OTP 位数（如 6、8）
     */
    public TOTPGenerator(OTPAlgorithm algorithm, int timePeriod, int digits) {
        this.algorithm = algorithm;
        this.timePeriod = timePeriod;
        this.digits = digits;
    }

    /**
     * 生成基于当前时间步的 OTP 值。
     *
     * @param secret    密钥
     * @param functor   当前时间（秒）
     * @param challenge 可选扩展参数
     * @return 格式化后的 OTP 字符串
     * @throws OTPGenerationException 如果哈希计算失败或结果为空
     */
    @Override
    public String generate(String secret, long functor, @Nullable String challenge) {
        AlgoFunc algoFunc = registry.get(this.algorithm.getAlgorithm());
        long bucket = Math.floorDiv(functor, this.timePeriod); // 计算时间桶
        byte[] compute = algoFunc.compute(secret, bucket, challenge);
        if (compute == null) {
            throw new OTPGenerationException("Generated OTP is invalid or empty.");
        }

        return getDigitsFromHash(compute);
    }

    /**
     * 从哈希结果中提取 OTP 值，使用动态截断技术。
     *
     * @param hash 哈希结果（由 HMAC 计算得出）
     * @return 指定位数的 OTP 字符串
     */
    private String getDigitsFromHash(byte[] hash) {
        // 动态截断偏移量（取最后一个字节的低 4 位）
        int offset = hash[hash.length - 1] & 0xF;

        long truncatedHash = 0;
        // 提取 4 个字节，组成一个 31 位正整数
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        // 清除最高位符号位，确保为正数
        truncatedHash &= 0x7FFFFFFF;
        // 对 10 的 digits 次方取模，确保位数一致
        truncatedHash %= Math.pow(10, digits);

        // 补齐前导 0，返回固定长度字符串
        return String.format("%0" + digits + "d", truncatedHash);
    }
}

