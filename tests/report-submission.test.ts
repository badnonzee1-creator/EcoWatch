// report-submission.test.ts
import { describe, expect, it, vi, beforeEach } from "vitest";

// Interfaces for type safety
interface ClarityResponse<T> {
  ok: boolean;
  value: T | number; // number for error codes
}

interface Geolocation {
  lat: number;
  long: number;
}

interface Report {
  reporter: string;
  geolocation: Geolocation;
  evidenceHash: Buffer; // Represent buff as Buffer
  threatType: string;
  description: string;
  timestamp: number;
  status: string;
  metadata: string;
}

interface ReportVersion {
  updatedEvidenceHash: Buffer;
  updateNotes: string;
  timestamp: number;
  updater: string;
}

interface ReportCategory {
  category: string;
  tags: string[];
}

interface Collaborator {
  role: string;
  permissions: string[];
  addedAt: number;
}

interface StatusHistory {
  status: string;
  visibility: boolean;
  timestamp: number;
  updater: string;
}

interface DataLicense {
  expiry: number;
  terms: string;
  active: boolean;
}

interface RevenueShare {
  percentage: number;
  totalReceived: number;
}

interface ContractState {
  paused: boolean;
  admin: string;
  reportCounter: number;
  reports: Map<number, Report>;
  reportVersions: Map<string, ReportVersion>; // Key: `${reportId}-${version}`
  reportCategories: Map<number, ReportCategory>;
  reportCollaborators: Map<string, Collaborator>; // Key: `${reportId}-${collaborator}`
  reportStatusHistory: Map<string, StatusHistory>; // Key: `${reportId}-${updateId}`
  dataLicenses: Map<string, DataLicense>; // Key: `${reportId}-${licensee}`
  revenueShares: Map<string, RevenueShare>; // Key: `${reportId}-${participant}`
}

// Mock contract implementation
class ReportSubmissionMock {
  private state: ContractState = {
    paused: false,
    admin: "deployer",
    reportCounter: 0,
    reports: new Map(),
    reportVersions: new Map(),
    reportCategories: new Map(),
    reportCollaborators: new Map(),
    reportStatusHistory: new Map(),
    dataLicenses: new Map(),
    revenueShares: new Map(),
  };

  private ERR_INVALID_INPUT = 1;
  private ERR_REPORT_EXISTS = 2;
  private ERR_UNAUTHORIZED = 3;
  private ERR_INVALID_STATUS = 4;
  private ERR_MAX_VERSIONS_REACHED = 5;
  private ERR_INVALID_LICENSE = 6;
  private ERR_INVALID_SHARE = 7;
  private ERR_PAUSED = 8;
  private MAX_VERSIONS = 10;
  private MAX_TAGS = 15;
  private MAX_PERMISSIONS = 10;
  private MAX_METADATA_LEN = 1024;

  private currentBlockHeight = 100; // Mock block height

  // Simulate block height increase
  private incrementBlockHeight() {
    this.currentBlockHeight += 1;
  }

  submitReport(
    caller: string,
    lat: number,
    long: number,
    evidenceHash: Buffer,
    threatType: string,
    description: string,
    metadata: string
  ): ClarityResponse<number> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    if (threatType.length === 0 || description.length === 0 || metadata.length > this.MAX_METADATA_LEN) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    const reportId = this.state.reportCounter + 1;
    // Check if report exists (mock: assume no duplicates by id)
    this.state.reports.set(reportId, {
      reporter: caller,
      geolocation: { lat, long },
      evidenceHash,
      threatType,
      description,
      timestamp: this.currentBlockHeight,
      status: "pending",
      metadata,
    });
    this.state.reportCounter = reportId;
    // Initialize status history
    this.state.reportStatusHistory.set(`${reportId}-1`, {
      status: "pending",
      visibility: true,
      timestamp: this.currentBlockHeight,
      updater: caller,
    });
    this.incrementBlockHeight();
    return { ok: true, value: reportId };
  }

  addReportVersion(
    caller: string,
    reportId: number,
    newEvidenceHash: Buffer,
    notes: string
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter && !this.hasPermission(reportId, caller, "edit")) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const versions = Array.from(this.state.reportVersions.keys()).filter(key => key.startsWith(`${reportId}-`)).length;
    if (versions >= this.MAX_VERSIONS) {
      return { ok: false, value: this.ERR_MAX_VERSIONS_REACHED };
    }
    const version = versions + 1;
    this.state.reportVersions.set(`${reportId}-${version}`, {
      updatedEvidenceHash: newEvidenceHash,
      updateNotes: notes,
      timestamp: this.currentBlockHeight,
      updater: caller,
    });
    this.incrementBlockHeight();
    return { ok: true, value: true };
  }

  addReportCategory(
    caller: string,
    reportId: number,
    category: string,
    tags: string[]
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (tags.length > this.MAX_TAGS) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    this.state.reportCategories.set(reportId, { category, tags });
    return { ok: true, value: true };
  }

  addCollaborator(
    caller: string,
    reportId: number,
    collaborator: string,
    role: string,
    permissions: string[]
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (permissions.length > this.MAX_PERMISSIONS) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    this.state.reportCollaborators.set(`${reportId}-${collaborator}`, {
      role,
      permissions,
      addedAt: this.currentBlockHeight,
    });
    return { ok: true, value: true };
  }

  updateReportStatus(
    caller: string,
    reportId: number,
    newStatus: string,
    visibility: boolean
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter && !this.hasPermission(reportId, caller, "verify")) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (!["pending", "verified", "rejected", "archived"].includes(newStatus)) {
      return { ok: false, value: this.ERR_INVALID_STATUS };
    }
    const historyKeys = Array.from(this.state.reportStatusHistory.keys()).filter(key => key.startsWith(`${reportId}-`));
    const updateId = historyKeys.length + 1;
    this.state.reports.set(reportId, { ...report, status: newStatus });
    this.state.reportStatusHistory.set(`${reportId}-${updateId}`, {
      status: newStatus,
      visibility,
      timestamp: this.currentBlockHeight,
      updater: caller,
    });
    this.incrementBlockHeight();
    return { ok: true, value: true };
  }

  grantLicense(
    caller: string,
    reportId: number,
    licensee: string,
    duration: number,
    terms: string
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (duration <= 0) {
      return { ok: false, value: this.ERR_INVALID_LICENSE };
    }
    this.state.dataLicenses.set(`${reportId}-${licensee}`, {
      expiry: this.currentBlockHeight + duration,
      terms,
      active: true,
    });
    return { ok: true, value: true };
  }

  setRevenueShare(
    caller: string,
    reportId: number,
    participant: string,
    sharePercentage: number
  ): ClarityResponse<boolean> {
    const report = this.state.reports.get(reportId);
    if (!report) {
      return { ok: false, value: this.ERR_INVALID_INPUT };
    }
    if (caller !== report.reporter) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (sharePercentage <= 0 || sharePercentage > 100) {
      return { ok: false, value: this.ERR_INVALID_SHARE };
    }
    this.state.revenueShares.set(`${reportId}-${participant}`, {
      percentage: sharePercentage,
      totalReceived: 0,
    });
    return { ok: true, value: true };
  }

  pauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = true;
    return { ok: true, value: true };
  }

  unpauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = false;
    return { ok: true, value: true };
  }

  setAdmin(caller: string, newAdmin: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.admin = newAdmin;
    return { ok: true, value: true };
  }

  getReport(reportId: number): ClarityResponse<Report | null> {
    return { ok: true, value: this.state.reports.get(reportId) ?? null };
  }

  getReportVersion(reportId: number, version: number): ClarityResponse<ReportVersion | null> {
    return { ok: true, value: this.state.reportVersions.get(`${reportId}-${version}`) ?? null };
  }

  getReportCategory(reportId: number): ClarityResponse<ReportCategory | null> {
    return { ok: true, value: this.state.reportCategories.get(reportId) ?? null };
  }

  getCollaborator(reportId: number, collaborator: string): ClarityResponse<Collaborator | null> {
    return { ok: true, value: this.state.reportCollaborators.get(`${reportId}-${collaborator}`) ?? null };
  }

  getStatusHistory(reportId: number, updateId: number): ClarityResponse<StatusHistory | null> {
    return { ok: true, value: this.state.reportStatusHistory.get(`${reportId}-${updateId}`) ?? null };
  }

  getLicense(reportId: number, licensee: string): ClarityResponse<DataLicense | null> {
    return { ok: true, value: this.state.dataLicenses.get(`${reportId}-${licensee}`) ?? null };
  }

  getRevenueShare(reportId: number, participant: string): ClarityResponse<RevenueShare | null> {
    return { ok: true, value: this.state.revenueShares.get(`${reportId}-${participant}`) ?? null };
  }

  isPaused(): ClarityResponse<boolean> {
    return { ok: true, value: this.state.paused };
  }

  private hasPermission(reportId: number, user: string, perm: string): boolean {
    const collab = this.state.reportCollaborators.get(`${reportId}-${user}`);
    return collab ? collab.permissions.includes(perm) : false;
  }
}

// Test setup
const accounts = {
  deployer: "deployer",
  reporter: "wallet_1",
  collaborator: "wallet_2",
  licensee: "wallet_3",
  participant: "wallet_4",
};

describe("ReportSubmission Contract", () => {
  let contract: ReportSubmissionMock;

  beforeEach(() => {
    contract = new ReportSubmissionMock();
    vi.resetAllMocks();
  });

  it("should allow reporter to submit a new report", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    const submitResult = contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );
    expect(submitResult).toEqual({ ok: true, value: 1 });

    const report = contract.getReport(1);
    expect(report).toEqual({
      ok: true,
      value: expect.objectContaining({
        reporter: accounts.reporter,
        threatType: "deforestation",
        status: "pending",
      }),
    });

    const statusHistory = contract.getStatusHistory(1, 1);
    expect(statusHistory).toEqual({
      ok: true,
      value: expect.objectContaining({
        status: "pending",
        visibility: true,
      }),
    });
  });

  it("should prevent submission when paused", () => {
    contract.pauseContract(accounts.deployer);
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    const submitResult = contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );
    expect(submitResult).toEqual({ ok: false, value: 8 });
  });

  it("should allow adding a version to a report", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const newEvidenceHash = Buffer.from("newhash12345678901234567890123456");
    const addVersion = contract.addReportVersion(
      accounts.reporter,
      1,
      newEvidenceHash,
      "Updated with new satellite image"
    );
    expect(addVersion).toEqual({ ok: true, value: true });

    const version = contract.getReportVersion(1, 1);
    expect(version).toEqual({
      ok: true,
      value: expect.objectContaining({
        updateNotes: "Updated with new satellite image",
      }),
    });
  });

  it("should prevent unauthorized user from adding version", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const newEvidenceHash = Buffer.from("newhash12345678901234567890123456");
    const addVersion = contract.addReportVersion(
      accounts.collaborator,
      1,
      newEvidenceHash,
      "Unauthorized update"
    );
    expect(addVersion).toEqual({ ok: false, value: 3 });
  });

  it("should allow adding category and tags", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const addCategory = contract.addReportCategory(
      accounts.reporter,
      1,
      "forest",
      ["amazon", "illegal-logging"]
    );
    expect(addCategory).toEqual({ ok: true, value: true });

    const category = contract.getReportCategory(1);
    expect(category).toEqual({
      ok: true,
      value: { category: "forest", tags: ["amazon", "illegal-logging"] },
    });
  });

  it("should allow adding collaborator with permissions", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const addCollab = contract.addCollaborator(
      accounts.reporter,
      1,
      accounts.collaborator,
      "verifier",
      ["edit", "verify"]
    );
    expect(addCollab).toEqual({ ok: true, value: true });

    const collab = contract.getCollaborator(1, accounts.collaborator);
    expect(collab).toEqual({
      ok: true,
      value: expect.objectContaining({
        role: "verifier",
        permissions: ["edit", "verify"],
      }),
    });
  });

  it("should allow collaborator with permission to update status", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    contract.addCollaborator(
      accounts.reporter,
      1,
      accounts.collaborator,
      "verifier",
      ["verify"]
    );

    const updateStatus = contract.updateReportStatus(
      accounts.collaborator,
      1,
      "verified",
      false
    );
    expect(updateStatus).toEqual({ ok: true, value: true });

    const report = contract.getReport(1);
    expect(report).toEqual({
      ok: true,
      value: expect.objectContaining({ status: "verified" }),
    });

    const history = contract.getStatusHistory(1, 2);
    expect(history).toEqual({
      ok: true,
      value: expect.objectContaining({
        status: "verified",
        visibility: false,
      }),
    });
  });

  it("should prevent invalid status update", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const updateStatus = contract.updateReportStatus(
      accounts.reporter,
      1,
      "invalid",
      true
    );
    expect(updateStatus).toEqual({ ok: false, value: 4 });
  });

  it("should allow granting license", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const grant = contract.grantLicense(
      accounts.reporter,
      1,
      accounts.licensee,
      1000,
      "Commercial use allowed"
    );
    expect(grant).toEqual({ ok: true, value: true });

    const license = contract.getLicense(1, accounts.licensee);
    expect(license).toEqual({
      ok: true,
      value: expect.objectContaining({
        terms: "Commercial use allowed",
        active: true,
      }),
    });
  });

  it("should allow setting revenue share", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const setShare = contract.setRevenueShare(
      accounts.reporter,
      1,
      accounts.participant,
      20
    );
    expect(setShare).toEqual({ ok: true, value: true });

    const share = contract.getRevenueShare(1, accounts.participant);
    expect(share).toEqual({
      ok: true,
      value: { percentage: 20, totalReceived: 0 },
    });
  });

  it("should prevent invalid revenue share percentage", () => {
    const evidenceHash = Buffer.from("dummyhash123456789012345678901234");
    contract.submitReport(
      accounts.reporter,
      40,
      -74,
      evidenceHash,
      "deforestation",
      "Trees being cut down",
      '{"severity": "high"}'
    );

    const setShare = contract.setRevenueShare(
      accounts.reporter,
      1,
      accounts.participant,
      150
    );
    expect(setShare).toEqual({ ok: false, value: 7 });
  });

  it("should allow admin to pause and unpause", () => {
    const pause = contract.pauseContract(accounts.deployer);
    expect(pause).toEqual({ ok: true, value: true });
    expect(contract.isPaused()).toEqual({ ok: true, value: true });

    const unpause = contract.unpauseContract(accounts.deployer);
    expect(unpause).toEqual({ ok: true, value: true });
    expect(contract.isPaused()).toEqual({ ok: true, value: false });
  });

  it("should prevent non-admin from pausing", () => {
    const pause = contract.pauseContract(accounts.reporter);
    expect(pause).toEqual({ ok: false, value: 3 });
  });
});