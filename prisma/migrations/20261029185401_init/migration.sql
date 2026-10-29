-- CreateTable
CREATE TABLE "User" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'analyst',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastLoginAt" DATETIME
);

-- CreateTable
CREATE TABLE "Session" (
    "sid" TEXT NOT NULL PRIMARY KEY,
    "data" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "LoginFailure" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL,
    "at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "Assessment" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "ticket" TEXT NOT NULL,
    "client" TEXT NOT NULL,
    "alertName" TEXT NOT NULL DEFAULT '',
    "rawLogs" TEXT NOT NULL DEFAULT '',
    "findings" TEXT NOT NULL DEFAULT '',
    "analystId" INTEGER,
    "analystName" TEXT NOT NULL DEFAULT '',
    "shift" TEXT NOT NULL DEFAULT 'Morning',
    "verdict" TEXT NOT NULL DEFAULT 'Auto',
    "severity" TEXT NOT NULL DEFAULT 'Low',
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "confidence" TEXT NOT NULL DEFAULT 'Low',
    "summary" TEXT NOT NULL DEFAULT '',
    "alertId" TEXT NOT NULL DEFAULT '',
    "rule" TEXT NOT NULL DEFAULT '',
    "ruleLogic" TEXT NOT NULL DEFAULT '',
    "detSource" TEXT NOT NULL DEFAULT '',
    "category" TEXT NOT NULL DEFAULT '',
    "alertSeverity" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT '',
    "created" TEXT NOT NULL DEFAULT '',
    "alertWindow" TEXT NOT NULL DEFAULT '',
    "asn" TEXT NOT NULL DEFAULT '',
    "location" TEXT NOT NULL DEFAULT '',
    "ipType" TEXT NOT NULL DEFAULT '',
    "reputation" TEXT NOT NULL DEFAULT '',
    "logSource" TEXT NOT NULL DEFAULT '',
    "edrTelemetry" TEXT NOT NULL DEFAULT '',
    "closure" TEXT NOT NULL DEFAULT 'Auto',
    "verdictReason" TEXT NOT NULL DEFAULT '',
    "extra" JSONB,
    "generatedReport" TEXT,
    "aiGenerated" BOOLEAN NOT NULL DEFAULT false,
    "escalatedAt" DATETIME,
    "escalationStatus" TEXT,
    "statusLog" JSONB,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Assessment_analystId_fkey" FOREIGN KEY ("analystId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Note" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "assessmentId" INTEGER NOT NULL,
    "type" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "authorId" INTEGER,
    "authorName" TEXT NOT NULL DEFAULT '',
    "auto" BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT "Note_assessmentId_fkey" FOREIGN KEY ("assessmentId") REFERENCES "Assessment" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Note_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "OsintResult" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "scope" TEXT NOT NULL,
    "userId" INTEGER,
    "assessmentId" INTEGER,
    "indicator" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "verdict" TEXT NOT NULL DEFAULT 'Not checked',
    "analystNote" TEXT NOT NULL DEFAULT '',
    "manual" BOOLEAN NOT NULL DEFAULT false,
    "hidden" BOOLEAN NOT NULL DEFAULT false,
    "providerData" JSONB,
    "checkedAt" DATETIME,
    "checkedBy" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "OsintResult_assessmentId_fkey" FOREIGN KEY ("assessmentId") REFERENCES "Assessment" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "OsintCache" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "indicator" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "response" JSONB NOT NULL,
    "fetchedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "Screenshot" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "userId" INTEGER NOT NULL,
    "page" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "takenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Screenshot_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Playbook" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client" TEXT NOT NULL,
    "industry" TEXT NOT NULL DEFAULT '',
    "reviewed" TEXT NOT NULL DEFAULT '',
    "matrix" JSONB NOT NULL,
    "contacts" JSONB NOT NULL,
    "containment" TEXT NOT NULL DEFAULT '',
    "benign" JSONB NOT NULL,
    "procedures" JSONB NOT NULL,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "ChecklistState" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "assessmentId" INTEGER NOT NULL,
    "item" TEXT NOT NULL,
    "done" BOOLEAN NOT NULL DEFAULT false,
    "doneBy" INTEGER,
    "doneAt" DATETIME,
    CONSTRAINT "ChecklistState_assessmentId_fkey" FOREIGN KEY ("assessmentId") REFERENCES "Assessment" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "userId" INTEGER,
    "action" TEXT NOT NULL,
    "target" TEXT NOT NULL DEFAULT '',
    "details" JSONB,
    "ip" TEXT NOT NULL DEFAULT '',
    "at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- CreateIndex
CREATE INDEX "LoginFailure_username_at_idx" ON "LoginFailure"("username", "at");

-- CreateIndex
CREATE INDEX "Assessment_escalatedAt_idx" ON "Assessment"("escalatedAt");

-- CreateIndex
CREATE INDEX "Assessment_createdAt_idx" ON "Assessment"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "Assessment_client_ticket_key" ON "Assessment"("client", "ticket");

-- CreateIndex
CREATE INDEX "Note_assessmentId_idx" ON "Note"("assessmentId");

-- CreateIndex
CREATE INDEX "OsintResult_assessmentId_idx" ON "OsintResult"("assessmentId");

-- CreateIndex
CREATE UNIQUE INDEX "OsintResult_scope_indicator_key" ON "OsintResult"("scope", "indicator");

-- CreateIndex
CREATE UNIQUE INDEX "OsintCache_provider_indicator_key" ON "OsintCache"("provider", "indicator");

-- CreateIndex
CREATE INDEX "Screenshot_userId_idx" ON "Screenshot"("userId");

-- CreateIndex
CREATE INDEX "Screenshot_takenAt_idx" ON "Screenshot"("takenAt");

-- CreateIndex
CREATE UNIQUE INDEX "Playbook_client_key" ON "Playbook"("client");

-- CreateIndex
CREATE UNIQUE INDEX "ChecklistState_assessmentId_item_key" ON "ChecklistState"("assessmentId", "item");

-- CreateIndex
CREATE INDEX "AuditLog_at_idx" ON "AuditLog"("at");
