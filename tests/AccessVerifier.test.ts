import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, uintCV } from "@stacks/transactions";

const ERR_INVALID_PROOF = 300;
const ERR_NO_ACCESS = 301;
const ERR_INVALID_COMMITMENT = 302;
const ERR_INVALID_CONTENT_ID = 303;
const ERR_INVALID_DURATION = 304;
const ERR_ACCESS_ALREADY_GRANTED = 305;
const ERR_ACCESS_EXPIRED = 306;
const ERR_NOT_OWNER = 307;
const ERR_INVALID_TIMESTAMP = 308;
const ERR_AUTHORITY_NOT_SET = 309;
const ERR_INVALID_MAX_DURATION = 310;
const ERR_INVALID_MIN_DURATION = 311;
const ERR_MAX_GRANTS_EXCEEDED = 312;
const ERR_INVALID_ACCESS_TYPE = 313;
const ERR_INVALID_PENALTY = 314;
const ERR_INVALID_VOTING_THRESHOLD = 315;
const ERR_GRANT_NOT_FOUND = 316;
const ERR_INVALID_UPDATE_PARAM = 317;
const ERR_UPDATE_NOT_ALLOWED = 318;
const ERR_INVALID_LOCATION = 319;
const ERR_INVALID_CURRENCY = 320;

interface Grant {
  grantedAt: number;
  expiresAt: number;
  accessType: number;
  penalty: number;
  votingThreshold: number;
  timestamp: number;
  granter: string;
  location: string;
  currency: string;
  status: boolean;
}

interface GrantUpdate {
  updateDuration: number;
  updateAccessType: number;
  updateTimestamp: number;
  updater: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class AccessVerifierMock {
  state: {
    nextGrantId: number;
    maxGrants: number;
    grantFee: number;
    authorityContract: string | null;
    maxDuration: number;
    minDuration: number;
    accessGrants: Map<string, Grant>;
    grantsByCommit: Map<string, number>;
    grantUpdates: Map<number, GrantUpdate>;
  } = {
    nextGrantId: 0,
    maxGrants: 10000,
    grantFee: 100,
    authorityContract: null,
    maxDuration: 525600,
    minDuration: 60,
    accessGrants: new Map(),
    grantsByCommit: new Map(),
    grantUpdates: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];
  identities: Map<string, { owner: string }> = new Map();

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextGrantId: 0,
      maxGrants: 10000,
      grantFee: 100,
      authorityContract: null,
      maxDuration: 525600,
      minDuration: 60,
      accessGrants: new Map(),
      grantsByCommit: new Map(),
      grantUpdates: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.stxTransfers = [];
    this.identities = new Map();
  }

  getIdentity(commitment: string): Result<{ owner: string }> {
    const identity = this.identities.get(commitment);
    if (!identity) return { ok: false, value: { owner: "" } };
    return { ok: true, value: identity };
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") {
      return { ok: false, value: false };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: false };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setGrantFee(newFee: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    if (newFee < 0) return { ok: false, value: false };
    this.state.grantFee = newFee;
    return { ok: true, value: true };
  }

  setMaxDuration(newMax: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    if (newMax <= this.state.minDuration) return { ok: false, value: false };
    this.state.maxDuration = newMax;
    return { ok: true, value: true };
  }

  setMinDuration(newMin: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    if (newMin >= this.state.maxDuration) return { ok: false, value: false };
    this.state.minDuration = newMin;
    return { ok: true, value: true };
  }

  setMaxGrants(newMax: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    if (newMax <= 0) return { ok: false, value: false };
    this.state.maxGrants = newMax;
    return { ok: true, value: true };
  }

  grantAccess(
    commitment: string,
    contentId: number,
    duration: number,
    accessType: number,
    penalty: number,
    votingThreshold: number,
    location: string,
    currency: string
  ): Result<number> {
    if (this.state.nextGrantId >= this.state.maxGrants) return { ok: false, value: ERR_MAX_GRANTS_EXCEEDED };
    if (commitment.length !== 64) return { ok: false, value: ERR_INVALID_COMMITMENT };
    if (contentId <= 0) return { ok: false, value: ERR_INVALID_CONTENT_ID };
    if (duration < this.state.minDuration || duration > this.state.maxDuration) return { ok: false, value: ERR_INVALID_DURATION };
    if (![0, 1, 2].includes(accessType)) return { ok: false, value: ERR_INVALID_ACCESS_TYPE };
    if (penalty > 100) return { ok: false, value: ERR_INVALID_PENALTY };
    if (votingThreshold <= 0 || votingThreshold > 100) return { ok: false, value: ERR_INVALID_VOTING_THRESHOLD };
    if (!location || location.length > 100) return { ok: false, value: ERR_INVALID_LOCATION };
    if (!["STX", "USD", "BTC"].includes(currency)) return { ok: false, value: ERR_INVALID_CURRENCY };
    const identity = this.getIdentity(commitment).value;
    if (identity.owner !== this.caller) return { ok: false, value: ERR_NOT_OWNER };
    const key = `${commitment}-${contentId}`;
    if (this.state.accessGrants.has(key)) return { ok: false, value: ERR_ACCESS_ALREADY_GRANTED };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_SET };

    this.stxTransfers.push({ amount: this.state.grantFee, from: this.caller, to: this.state.authorityContract });

    const id = this.state.nextGrantId;
    const expires = this.blockHeight + duration;
    const grant: Grant = {
      grantedAt: this.blockHeight,
      expiresAt: expires,
      accessType,
      penalty,
      votingThreshold,
      timestamp: this.blockHeight,
      granter: this.caller,
      location,
      currency,
      status: true,
    };
    this.state.accessGrants.set(key, grant);
    this.state.grantsByCommit.set(commitment, id);
    this.state.nextGrantId++;
    return { ok: true, value: id };
  }

  getGrant(commitment: string, contentId: number): Grant | null {
    const key = `${commitment}-${contentId}`;
    return this.state.accessGrants.get(key) || null;
  }

  updateGrant(commitment: string, contentId: number, updateDuration: number, updateAccessType: number): Result<boolean> {
    const key = `${commitment}-${contentId}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant) return { ok: false, value: false };
    if (grant.granter !== this.caller) return { ok: false, value: false };
    if (updateDuration < this.state.minDuration || updateDuration > this.state.maxDuration) return { ok: false, value: false };
    if (![0, 1, 2].includes(updateAccessType)) return { ok: false, value: false };

    const newExpires = this.blockHeight + updateDuration;
    const updated: Grant = {
      ...grant,
      expiresAt: newExpires,
      accessType: updateAccessType,
      timestamp: this.blockHeight,
    };
    this.state.accessGrants.set(key, updated);
    const grantId = this.state.grantsByCommit.get(commitment);
    if (grantId !== undefined) {
      this.state.grantUpdates.set(grantId, {
        updateDuration,
        updateAccessType,
        updateTimestamp: this.blockHeight,
        updater: this.caller,
      });
    }
    return { ok: true, value: true };
  }

  revokeGrant(commitment: string, contentId: number): Result<boolean> {
    const key = `${commitment}-${contentId}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant) return { ok: false, value: false };
    if (grant.granter !== this.caller) return { ok: false, value: false };
    const updated: Grant = { ...grant, status: false };
    this.state.accessGrants.set(key, updated);
    return { ok: true, value: true };
  }

  hasAccess(commitment: string, contentId: number): boolean {
    const key = `${commitment}-${contentId}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant) return false;
    return grant.status && grant.expiresAt > this.blockHeight;
  }

  getGrantCount(): Result<number> {
    return { ok: true, value: this.state.nextGrantId };
  }

  checkGrantExistence(commitment: string): Result<boolean> {
    return { ok: true, value: this.state.grantsByCommit.has(commitment) };
  }
}

describe("AccessVerifier", () => {
  let contract: AccessVerifierMock;

  beforeEach(() => {
    contract = new AccessVerifierMock();
    contract.reset();
  });

  it("grants access successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    const result = contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const grant = contract.getGrant(commitment, 1);
    expect(grant?.accessType).toBe(0);
    expect(grant?.penalty).toBe(5);
    expect(grant?.votingThreshold).toBe(50);
    expect(grant?.location).toBe("LocationX");
    expect(grant?.currency).toBe("STX");
    expect(grant?.status).toBe(true);
    expect(contract.stxTransfers).toEqual([{ amount: 100, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects duplicate grants", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    const result = contract.grantAccess(
      commitment,
      1,
      7200,
      1,
      10,
      60,
      "LocationY",
      "USD"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ACCESS_ALREADY_GRANTED);
  });

  it("rejects non-owner grant", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST3FAKE" });
    const result = contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_OWNER);
  });

  it("rejects grant without authority contract", () => {
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    const result = contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUTHORITY_NOT_SET);
  });

  it("rejects invalid duration", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    const result = contract.grantAccess(
      commitment,
      1,
      30,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_DURATION);
  });

  it("rejects invalid access type", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    const result = contract.grantAccess(
      commitment,
      1,
      3600,
      3,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_ACCESS_TYPE);
  });

  it("updates grant successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    const result = contract.updateGrant(commitment, 1, 7200, 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const grant = contract.getGrant(commitment, 1);
    expect(grant?.expiresAt).toBe(7200);
    expect(grant?.accessType).toBe(1);
    const update = contract.state.grantUpdates.get(0);
    expect(update?.updateDuration).toBe(7200);
    expect(update?.updateAccessType).toBe(1);
    expect(update?.updater).toBe("ST1TEST");
  });

  it("rejects update for non-existent grant", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    const result = contract.updateGrant(commitment, 1, 7200, 1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects update by non-granter", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    contract.caller = "ST3FAKE";
    const result = contract.updateGrant(commitment, 1, 7200, 1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("revokes grant successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    const result = contract.revokeGrant(commitment, 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const grant = contract.getGrant(commitment, 1);
    expect(grant?.status).toBe(false);
  });

  it("checks has access correctly", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(contract.hasAccess(commitment, 1)).toBe(true);
    contract.blockHeight = 3601;
    expect(contract.hasAccess(commitment, 1)).toBe(false);
  });

  it("sets grant fee successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.setGrantFee(200);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.grantFee).toBe(200);
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    expect(contract.stxTransfers).toEqual([{ amount: 200, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects grant fee change without authority", () => {
    const result = contract.setGrantFee(200);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("returns correct grant count", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment1 = "a".repeat(64);
    const commitment2 = "b".repeat(64);
    contract.identities.set(commitment1, { owner: "ST1TEST" });
    contract.identities.set(commitment2, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment1,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    contract.grantAccess(
      commitment2,
      2,
      7200,
      1,
      10,
      60,
      "LocationY",
      "USD"
    );
    const result = contract.getGrantCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks grant existence correctly", () => {
    contract.setAuthorityContract("ST2TEST");
    const commitment = "a".repeat(64);
    contract.identities.set(commitment, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    const result = contract.checkGrantExistence(commitment);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const result2 = contract.checkGrantExistence("nonexistent");
    expect(result2.ok).toBe(true);
    expect(result2.value).toBe(false);
  });

  it("parses content id with Clarity", () => {
    const cv = uintCV(1);
    expect(cv.value).toEqual(BigInt(1));
  });

  it("rejects grant with max grants exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.state.maxGrants = 1;
    const commitment1 = "a".repeat(64);
    contract.identities.set(commitment1, { owner: "ST1TEST" });
    contract.grantAccess(
      commitment1,
      1,
      3600,
      0,
      5,
      50,
      "LocationX",
      "STX"
    );
    const commitment2 = "b".repeat(64);
    contract.identities.set(commitment2, { owner: "ST1TEST" });
    const result = contract.grantAccess(
      commitment2,
      2,
      7200,
      1,
      10,
      60,
      "LocationY",
      "USD"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_GRANTS_EXCEEDED);
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects invalid authority contract", () => {
    const result = contract.setAuthorityContract("SP000000000000000000002Q6VF78");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });
});