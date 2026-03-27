-- AlterTable
ALTER TABLE "User" ADD COLUMN "toss_user_key" VARCHAR(255);

-- CreateIndex
CREATE UNIQUE INDEX "User_toss_user_key_key" ON "User"("toss_user_key");
