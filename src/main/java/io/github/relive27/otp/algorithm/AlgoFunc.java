package io.github.relive27.otp.algorithm;


import io.github.relive27.otp.exception.OTPGenerationException;

import javax.annotation.Nullable;


/**
 * 表示一次性密码（OTP）算法的通用计算函数接口。
 * <p>
 * 实现类需根据指定的密钥、因子（时间步或计数器）以及可选的挑战参数生成 OTP 所需的哈希值。
 * 通常用于 TOTP（基于时间）或 HOTP（基于计数器）算法中。
 * </p>
 *
 * @author: ReLive27
 * @date: 2025/5/28 22:10
 */
@FunctionalInterface
public interface AlgoFunc {

    /**
     * 计算 OTP 的哈希值。
     *
     * @param secret    密钥字符串
     * @param factor    因子值：TOTP 为当前时间步，HOTP 为递增计数器
     * @param challenge 可选的挑战参数
     * @return 表示 OTP 哈希结果的字节数组
     * @throws OTPGenerationException 当密钥无效、算法不可用或计算失败时抛出
     */
    byte[] compute(String secret, long factor, @Nullable String challenge) throws OTPGenerationException;
}

