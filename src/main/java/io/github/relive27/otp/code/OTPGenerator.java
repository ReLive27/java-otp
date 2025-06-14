package io.github.relive27.otp.code;


import io.github.relive27.otp.algorithm.AlgoFunc;

import javax.annotation.Nullable;


/**
 * 表示一次性密码（OTP）生成器接口，负责将密钥、因子等信息转换为最终的 OTP 字符串。
 * <p>
 * 通常结合 {@link AlgoFunc} 接口提供的哈希值计算结果，应用动态截断、进制转换等规则生成 OTP 值。
 * </p>
 *
 * @author: ReLive27
 * @date: 2025/5/28 22:09
 */
@FunctionalInterface
public interface OTPGenerator {

    /**
     * 生成 OTP 字符串。
     *
     * @param secret    密钥字符串（
     * @param functor   时间步（TOTP）或计数器（HOTP）
     * @param challenge 可选的挑战参数
     * @return 最终生成的一次性密码字符串
     */
    String generate(String secret, long functor, @Nullable String challenge);
}

