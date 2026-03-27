import { Request, Response } from "express";
import axios from "axios";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import prisma from "../db";

// JWT_SECRET 가져오기
const JWT_SECRET = (() => {
  if (!process.env.JWT_SECRET) {
    if (process.env.NODE_ENV === "production") {
      console.error(
        "⚠️  CRITICAL: JWT_SECRET is not set in production! This is a serious security risk."
      );
      process.exit(1);
    }
    console.warn(
      "⚠️  JWT_SECRET not set. Using default for development only!"
    );
    return "dev-jwt-secret-change-in-production";
  }
  return process.env.JWT_SECRET;
})();

const TOSS_API_BASE_URL =
  process.env.TOSS_API_BASE_URL || "https://apps-in-toss-api.toss.im";

/**
 * AES-256-GCM 복호화 (토스 개인정보)
 * 토스에서 제공하는 암호화된 필드는 Base64 인코딩된 "iv:ciphertext:authTag" 형태
 */
function decryptTossField(encryptedValue: string): string {
  const aesKeyBase64 = process.env.TOSS_AES_KEY;
  const aad = process.env.TOSS_AAD;

  if (!aesKeyBase64 || !aad) {
    throw new Error("TOSS_AES_KEY 또는 TOSS_AAD 환경 변수가 설정되지 않았습니다.");
  }

  const key = Buffer.from(aesKeyBase64, "base64");

  // 토스 암호화 포맷: Base64로 인코딩된 전체 값을 디코딩하면
  // 첫 12바이트 = IV, 마지막 16바이트 = AuthTag, 나머지 = ciphertext
  const encrypted = Buffer.from(encryptedValue, "base64");

  const iv = encrypted.subarray(0, 12);
  const authTag = encrypted.subarray(encrypted.length - 16);
  const ciphertext = encrypted.subarray(12, encrypted.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  decipher.setAAD(Buffer.from(aad, "utf8"));

  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString("utf8");
}

/**
 * POST /api/toss-login
 * 토스 로그인 처리
 * Body: { authorizationCode: string, referrer: string }
 */
export const tossLogin = async (req: Request, res: Response): Promise<void> => {
  try {
    const { authorizationCode, referrer } = req.body;

    if (!authorizationCode || !referrer) {
      res.status(400).json({
        message: "authorizationCode와 referrer가 필요합니다.",
      });
      return;
    }

    // 1. 토스 API로 accessToken 발급
    let tossAccessToken: string;
    try {
      const tokenResponse = await axios.post(
        `${TOSS_API_BASE_URL}/api-partner/v1/apps-in-toss/user/oauth2/generate-token`,
        { authorizationCode, referrer }
      );
      tossAccessToken = tokenResponse.data.accessToken;
    } catch (error: any) {
      console.error(
        "토스 토큰 발급 실패:",
        error.response?.data || error.message
      );
      res.status(401).json({
        message: "토스 인증에 실패했습니다.",
        error: "TOSS_TOKEN_ERROR",
      });
      return;
    }

    // 2. 토스 API로 사용자 정보 조회
    let tossUser: any;
    try {
      const userResponse = await axios.get(
        `${TOSS_API_BASE_URL}/api-partner/v1/apps-in-toss/user/oauth2/login-me`,
        {
          headers: {
            Authorization: `Bearer ${tossAccessToken}`,
          },
        }
      );
      tossUser = userResponse.data;
    } catch (error: any) {
      console.error(
        "토스 사용자 정보 조회 실패:",
        error.response?.data || error.message
      );
      res.status(401).json({
        message: "토스 사용자 정보를 가져올 수 없습니다.",
        error: "TOSS_USER_INFO_ERROR",
      });
      return;
    }

    const { userKey } = tossUser;

    if (!userKey) {
      res.status(400).json({
        message: "토스 사용자 키를 확인할 수 없습니다.",
        error: "TOSS_NO_USER_KEY",
      });
      return;
    }

    // 3. 개인정보 복호화 (선택적 - 필드가 있을 때만)
    let decryptedName: string | null = null;
    let decryptedEmail: string | null = null;
    let decryptedGender: string | null = null;

    try {
      if (tossUser.name) {
        decryptedName = decryptTossField(tossUser.name);
      }
      if (tossUser.email) {
        decryptedEmail = decryptTossField(tossUser.email);
      }
      if (tossUser.gender) {
        decryptedGender = decryptTossField(tossUser.gender);
      }
    } catch (error) {
      console.error("토스 개인정보 복호화 실패:", error);
      // 복호화 실패해도 로그인은 계속 진행 (userKey만으로도 식별 가능)
    }

    // 4. 기존 사용자 찾기 또는 새로 생성
    let user = await prisma.user.findUnique({
      where: { toss_user_key: userKey },
    });

    if (!user) {
      // 새 사용자 생성
      const salt = crypto.randomBytes(16).toString("hex");
      const randomPassword = crypto.randomBytes(32).toString("hex");
      const hashedPassword = crypto
        .pbkdf2Sync(randomPassword, salt, 10000, 64, "sha512")
        .toString("hex");

      user = await prisma.user.create({
        data: {
          toss_user_key: userKey,
          email: decryptedEmail || `toss_${userKey}@moodlog.app`,
          username: decryptedName || "무드로거",
          profile_name: decryptedName || "무드로거",
          password: hashedPassword,
          salt: salt,
          gender: decryptedGender || null,
          login_type: "toss",
        },
      });
    }

    // 5. JWT 토큰 발급
    const token = jwt.sign(
      {
        userId: user.user_id,
        profileName: user.profile_name || user.username,
      },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.status(200).json({
      message: "토스 로그인 성공",
      token,
      user: {
        user_id: user.user_id,
        email: user.email,
        profile_name: user.profile_name,
        profile_picture: user.profile_picture,
      },
    });
  } catch (error) {
    console.error("토스 로그인 오류:", error);
    res.status(500).json({
      message: "토스 로그인 중 오류가 발생했습니다.",
      error: "TOSS_LOGIN_ERROR",
    });
  }
};

/**
 * POST /api/toss-unlink
 * 토스 연결 해제 콜백
 * Body: { userKey: string, referrer: string }
 * referrer: "UNLINK" | "WITHDRAWAL_TERMS" | "WITHDRAWAL_TOSS"
 * Header: Authorization: Basic base64(username:password)
 */
export const tossUnlink = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    // Basic Auth 검증
    const authHeader = req.headers.authorization;
    const expectedUsername = process.env.TOSS_CALLBACK_USERNAME;
    const expectedPassword = process.env.TOSS_CALLBACK_PASSWORD;

    if (expectedUsername && expectedPassword) {
      if (!authHeader || !authHeader.startsWith("Basic ")) {
        res.status(401).json({ message: "인증이 필요합니다." });
        return;
      }

      const base64Credentials = authHeader.split(" ")[1];
      const credentials = Buffer.from(base64Credentials, "base64").toString("utf8");
      const [username, password] = credentials.split(":");

      if (username !== expectedUsername || password !== expectedPassword) {
        res.status(401).json({ message: "인증에 실패했습니다." });
        return;
      }
    }

    const { userKey, referrer } = req.body;

    if (!userKey || !referrer) {
      res.status(400).json({
        message: "userKey와 referrer가 필요합니다.",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { toss_user_key: userKey },
    });

    if (!user) {
      // 사용자가 없어도 토스에는 성공으로 응답 (이미 삭제된 경우 등)
      res.status(200).json({ message: "처리 완료" });
      return;
    }

    switch (referrer) {
      case "UNLINK":
        // 사용자가 토스에서 연결 해제 -> toss_user_key 제거, login_type 변경
        await prisma.user.update({
          where: { user_id: user.user_id },
          data: {
            toss_user_key: null,
            login_type: "unlinked",
          },
        });
        break;

      case "WITHDRAWAL_TERMS":
      case "WITHDRAWAL_TOSS":
        // 토스 탈퇴 또는 약관 철회 -> 사용자 데이터 삭제
        await prisma.user.delete({
          where: { user_id: user.user_id },
        });
        break;

      default:
        console.warn(`알 수 없는 toss unlink referrer: ${referrer}`);
        break;
    }

    res.status(200).json({ message: "처리 완료" });
  } catch (error) {
    console.error("토스 연결 해제 오류:", error);
    res.status(500).json({
      message: "토스 연결 해제 중 오류가 발생했습니다.",
      error: "TOSS_UNLINK_ERROR",
    });
  }
};
