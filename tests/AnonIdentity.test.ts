import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_PREIMAGE = 101;
const ERR_INVALID_COMMITMENT = 102;
const ERR_ID_ALREADY_EXISTS = 103;
const ERR_ID_NOT_FOUND = 104;
const ERR_NOT_OWNER = 105;
const ERR_AUTHORITY_NOT_VERIFIED = 107;
const ERR_INVALID_METADATA = 108;
const ERR_INVALID_EXPIRY = 109;
const ERR_ID_EXPIRED = 110;
const ERR_MAX_IDS_EXCEEDED = 112;
const ERR_INVALID_ID_TYPE = 113;
const ERR_INVALID_FEE = 114;
const ERR_INVALID_BLACKLIST_REASON = 117;
const ERR_ALREADY_BLACKLISTED = 118;
const ERR_NOT_BLACKLISTED = 119;
const ERR_INVALID_OWNER = 120;

interface Identity {
  commitment: Uint8Array;
  preimageHash: Uint8Array;
  metadata: Uint8Array;
  expiry: number;
  timestamp: number;
  owner: string;
  idType: string;
  status: boolean;
  revealCount: number;
}

interface IdentityUpdate {
  updateMetadata: Uint8Array;
  updateExpiry: number;
  updateTimestamp: number;
  updater: string;
}

interface BlacklistInfo {
  reason: string;
  blacklistedAt: number;
  blacklister: string;
}

type Result<T> = { ok: true; value: T } | { ok: false; value: number };

class AnonIdentityMock {
  state: {
    nextId: number;
    maxIds: number;
    creationFee: number;
    authorityContract: string | null;
    identities: Map<number, Identity>;
    identityUpdates: Map<number, IdentityUpdate>;
    identitiesByCommitment: Map<string, number>;
    blacklistedIds: Map<number, BlacklistInfo>;
  } = {
    nextId: 0,
    maxIds: 1000000,
    creationFee: 10,
    authorityContract: null,
    identities: new Map(),
    identityUpdates: new Map(),
    identitiesByCommitment: new Map(),
    blacklistedIds: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextId: 0,
      maxIds: 1000000,
      creationFee: 10,
      authorityContract: null,
      identities: new Map(),
      identityUpdates: new Map(),
      identitiesByCommitment: new Map(),
      blacklistedIds: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.stxTransfers = [];
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") {
      return { ok: false, value: ERR_INVALID_OWNER };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setCreationFee(newFee: number): Result<boolean> {
    if (newFee < 0) return { ok: false, value: ERR_INVALID_FEE };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };
    this.state.creationFee = newFee;
    return { ok: true, value: true };
  }

  setMaxIds(newMax: number): Result<boolean> {
    if (newMax <= 0) return { ok: false, value: ERR_MAX_IDS_EXCEEDED };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };
    this.state.maxIds = newMax;
    return { ok: true, value: true };
  }

  createIdentity(
    preimage: Uint8Array,
    metadata: Uint8Array,
    expiry: number,
    idType: string
  ): Result<number> {
    if (this.state.nextId >= this.state.maxIds) return { ok: false, value: ERR_MAX_IDS_EXCEEDED };
    if (preimage.length === 0) return { ok: false, value: ERR_INVALID_PREIMAGE };
    const commitment = this.hash160(preimage);
    if (commitment.length !== 32) return { ok: false, value: ERR_INVALID_COMMITMENT };
    if (metadata.length > 128) return { ok: false, value: ERR_INVALID_METADATA };
    if (expiry <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRY };
    if (!["anon", "pseudonym", "verified"].includes(idType)) return { ok: false, value: ERR_INVALID_ID_TYPE };
    const commitmentKey = this.buffToString(commitment);
    if (this.state.identitiesByCommitment.has(commitmentKey)) return { ok: false, value: ERR_ID_ALREADY_EXISTS };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };

    this.stxTransfers.push({ amount: this.state.creationFee, from: this.caller, to: this.state.authorityContract });

    const id = this.state.nextId;
    const identity: Identity = {
      commitment,
      preimageHash: this.sha256(preimage),
      metadata,
      expiry,
      timestamp: this.blockHeight,
      owner: this.caller,
      idType,
      status: true,
      revealCount: 0,
    };
    this.state.identities.set(id, identity);
    this.state.identitiesByCommitment.set(commitmentKey, id);
    this.state.nextId++;
    return { ok: true, value: id };
  }

  getIdentity(id: number): Identity | null {
    return this.state.identities.get(id) || null;
  }

  updateIdentity(id: number, updateMetadata: Uint8Array, updateExpiry: number): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };
    if (identity.owner !== this.caller) return { ok: false, value: ERR_NOT_OWNER };
    if (identity.expiry <= this.blockHeight) return { ok: false, value: ERR_ID_EXPIRED };
    if (this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_ALREADY_BLACKLISTED };
    if (updateMetadata.length > 128) return { ok: false, value: ERR_INVALID_METADATA };
    if (updateExpiry <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRY };

    const updated: Identity = {
      ...identity,
      metadata: updateMetadata,
      expiry: updateExpiry,
      timestamp: this.blockHeight,
    };
    this.state.identities.set(id, updated);
    this.state.identityUpdates.set(id, {
      updateMetadata,
      updateExpiry,
      updateTimestamp: this.blockHeight,
      updater: this.caller,
    });
    return { ok: true, value: true };
  }

  revealIdentity(id: number, preimage: Uint8Array, _context: string): Result<Identity> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };
    if (identity.expiry <= this.blockHeight) return { ok: false, value: ERR_ID_EXPIRED };
    if (this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_ALREADY_BLACKLISTED };
    if (identity.owner !== this.caller) return { ok: false, value: ERR_NOT_OWNER };
    if (!this.buffersEqual(this.sha256(preimage), identity.preimageHash)) return { ok: false, value: ERR_INVALID_PREIMAGE };
    if (!this.buffersEqual(this.hash160(preimage), identity.commitment)) return { ok: false, value: ERR_INVALID_COMMITMENT };

    const updated: Identity = {
      ...identity,
      revealCount: identity.revealCount + 1,
    };
    this.state.identities.set(id, updated);
    return { ok: true, value: updated };
  }

  blacklistIdentity(id: number, reason: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };
    if (this.caller !== this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (reason.length === 0) return { ok: false, value: ERR_INVALID_BLACKLIST_REASON };
    if (this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_ALREADY_BLACKLISTED };
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };

    this.state.blacklistedIds.set(id, {
      reason,
      blacklistedAt: this.blockHeight,
      blacklister: this.caller,
    });
    const updated: Identity = { ...identity, status: false };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  unblacklistIdentity(id: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };
    if (this.caller !== this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_NOT_BLACKLISTED };
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };

    this.state.blacklistedIds.delete(id);
    const updated: Identity = { ...identity, status: true };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  transferIdentityOwnership(id: number, newOwner: string): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };
    if (identity.expiry <= this.blockHeight) return { ok: false, value: ERR_ID_EXPIRED };
    if (this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_ALREADY_BLACKLISTED };
    if (identity.owner !== this.caller) return { ok: false, value: ERR_NOT_OWNER };
    if (newOwner === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_OWNER };

    const updated: Identity = { ...identity, owner: newOwner };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  getIdCount(): Result<number> {
    return { ok: true, value: this.state.nextId };
  }

  checkIdExistence(commitment: Uint8Array): Result<boolean> {
    return { ok: true, value: this.state.identitiesByCommitment.has(this.buffToString(commitment)) };
  }

  verifyOwnership(commitment: Uint8Array, preimage: Uint8Array): Result<boolean> {
    const expectedCommit = this.hash160(preimage);
    if (!this.buffersEqual(commitment, expectedCommit)) return { ok: false, value: ERR_INVALID_COMMITMENT };
    const commitmentKey = this.buffToString(commitment);
    const id = this.state.identitiesByCommitment.get(commitmentKey);
    if (id === undefined) return { ok: false, value: ERR_ID_NOT_FOUND };
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: ERR_ID_NOT_FOUND };
    if (identity.expiry <= this.blockHeight) return { ok: false, value: ERR_ID_EXPIRED };
    if (this.state.blacklistedIds.has(id)) return { ok: false, value: ERR_ALREADY_BLACKLISTED };
    return { ok: true, value: identity.owner === this.caller };
  }

  public hash160(_buff: Uint8Array): Uint8Array {
    return new Uint8Array(32).fill(0);
  }

  private sha256(_buff: Uint8Array): Uint8Array {
    return new Uint8Array(32).fill(0);
  }

  private buffToString(_buff: Uint8Array): string {
    return Array.from(_buff).join(",");
  }

  private buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

describe("AnonIdentity", () => {
  let contract: AnonIdentityMock;

  beforeEach(() => {
    contract = new AnonIdentityMock();
    contract.reset();
  });

  it("creates an identity successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    const result = contract.createIdentity(preimage, metadata, 100, "anon");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(0);

    const identity = contract.getIdentity(0);
    expect(identity?.idType).toBe("anon");
    expect(identity?.expiry).toBe(100);
    expect(identity?.owner).toBe("ST1TEST");
    expect(contract.stxTransfers).toEqual([{ amount: 10, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects duplicate commitments", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const result = contract.createIdentity(preimage, metadata, 200, "pseudonym");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_ID_ALREADY_EXISTS);
  });

  it("rejects identity creation without authority contract", () => {
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    const result = contract.createIdentity(preimage, metadata, 100, "anon");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_AUTHORITY_NOT_VERIFIED);
  });

  it("rejects invalid expiry", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    const result = contract.createIdentity(preimage, metadata, 0, "anon");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_INVALID_EXPIRY);
  });

  it("rejects invalid id type", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    const result = contract.createIdentity(preimage, metadata, 100, "invalid");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_INVALID_ID_TYPE);
  });

  it("updates an identity successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const updateMetadata = new Uint8Array(20).fill(3);
    const result = contract.updateIdentity(0, updateMetadata, 200);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.expiry).toBe(200);
    const update = contract.state.identityUpdates.get(0);
    expect(update?.updateExpiry).toBe(200);
    expect(update?.updater).toBe("ST1TEST");
  });

  it("rejects update for non-existent identity", () => {
    contract.setAuthorityContract("ST2TEST");
    const updateMetadata = new Uint8Array(20).fill(3);
    const result = contract.updateIdentity(99, updateMetadata, 200);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_ID_NOT_FOUND);
  });

  it("rejects update by non-owner", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    contract.caller = "ST3FAKE";
    const updateMetadata = new Uint8Array(20).fill(3);
    const result = contract.updateIdentity(0, updateMetadata, 200);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_NOT_OWNER);
  });

  it("sets creation fee successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.setCreationFee(20);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    expect(contract.state.creationFee).toBe(20);
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    expect(contract.stxTransfers).toEqual([{ amount: 20, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects creation fee change without authority contract", () => {
    const result = contract.setCreationFee(20);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_AUTHORITY_NOT_VERIFIED);
  });

  it("checks id existence correctly", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const commitment = contract.hash160(preimage);
    const result = contract.checkIdExistence(commitment);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    const fakeCommitment = new Uint8Array(32).fill(5);
    const result2 = contract.checkIdExistence(fakeCommitment);
    expect(result2.ok).toBe(true);
    if (!result2.ok) throw new Error("Unexpected error");
    expect(result2.value).toBe(false);
  });

  it("rejects identity creation with empty preimage", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(0);
    const metadata = new Uint8Array(10).fill(2);
    const result = contract.createIdentity(preimage, metadata, 100, "anon");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_INVALID_PREIMAGE);
  });

  it("rejects identity creation with max ids exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.state.maxIds = 1;
    const preimage1 = new Uint8Array(32).fill(1);
    const metadata1 = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage1, metadata1, 100, "anon");
    const preimage2 = new Uint8Array(32).fill(3);
    const metadata2 = new Uint8Array(10).fill(4);
    const result = contract.createIdentity(preimage2, metadata2, 200, "pseudonym");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_MAX_IDS_EXCEEDED);
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects invalid authority contract", () => {
    const result = contract.setAuthorityContract("SP000000000000000000002Q6VF78");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_INVALID_OWNER);
  });

  it("reveals identity successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const result = contract.revealIdentity(0, preimage, "test-context");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value.revealCount).toBe(1);
  });

  it("rejects reveal for expired identity", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    contract.blockHeight = 101;
    const result = contract.revealIdentity(0, preimage, "test-context");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unexpected success");
    expect(result.value).toBe(ERR_ID_EXPIRED);
  });

  it("blacklists identity successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    contract.caller = "ST2TEST";
    const result = contract.blacklistIdentity(0, "violation");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.status).toBe(false);
    const blacklist = contract.state.blacklistedIds.get(0);
    expect(blacklist?.reason).toBe("violation");
  });

  it("unblacklists identity successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    contract.caller = "ST2TEST";
    contract.blacklistIdentity(0, "violation");
    const result = contract.unblacklistIdentity(0);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.status).toBe(true);
    expect(contract.state.blacklistedIds.has(0)).toBe(false);
  });

  it("transfers ownership successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const result = contract.transferIdentityOwnership(0, "ST3NEW");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.owner).toBe("ST3NEW");
  });

  it("verifies ownership successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const preimage = new Uint8Array(32).fill(1);
    const metadata = new Uint8Array(10).fill(2);
    contract.createIdentity(preimage, metadata, 100, "anon");
    const commitment = contract.hash160(preimage);
    const result = contract.verifyOwnership(commitment, preimage);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("Unexpected error");
    expect(result.value).toBe(true);
  });

  it("parses identity parameters with Clarity types", () => {
    const idType = stringUtf8CV("anon");
    const expiry = uintCV(100);
    expect(idType.value).toBe("anon");
    expect(expiry.value).toEqual(BigInt(100));
  });
});