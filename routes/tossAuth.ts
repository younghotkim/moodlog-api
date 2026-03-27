import express from "express";
import * as tossAuthController from "../controllers/tossAuthController";

const router = express.Router();

// 토스 로그인
router.post("/toss-login", tossAuthController.tossLogin);

// 토스 연결 해제 콜백
router.post("/toss-unlink", tossAuthController.tossUnlink);

export default router;
