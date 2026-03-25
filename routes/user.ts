import express, { Request, Response } from "express";
import * as userController from "../controllers/userController";
import { authenticateToken, verifyUserOwnership } from "../middleware/auth";

const router = express.Router();

// Public routes
router.post("/register", userController.register);
router.post("/login", userController.login);
router.post("/check-email", (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({ message: "Email is required" });
    return;
  }

  userController.checkDuplicateEmail(email, (err, isDuplicate) => {
    if (err) {
      res.status(500).json({ message: "Internal server error", error: err });
      return;
    }

    if (isDuplicate) {
      res.status(409).json({ message: "Email already exists" });
      return;
    }

    res.status(200).json({ message: "Email is available" });
  });
});

router.post("/guest-login", userController.guestLogin);

// Protected routes - require authentication
router.get(
  "/user/:user_id",
  authenticateToken,
  verifyUserOwnership,
  userController.getUser
);
router.put(
  "/user",
  authenticateToken,
  verifyUserOwnership,
  userController.updateUser
);
router.delete(
  "/user/:user_id",
  authenticateToken,
  verifyUserOwnership,
  userController.deleteUser
);

export default router;
