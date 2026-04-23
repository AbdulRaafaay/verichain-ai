const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AuditLedger", function () {
  let AuditLedger;
  let auditLedger;
  let owner, gateway, admin;

  beforeEach(async function () {
    [owner, gateway, admin] = await ethers.getSigners();

    AuditLedger = await ethers.getContractFactory("AuditLedger");
    auditLedger = await AuditLedger.deploy(gateway.address);
  });

  describe("Anchoring", function () {
    it("Should allow Gateway to anchor Merkle root", async function () {
      const root = ethers.keccak256(ethers.toUtf8Bytes("merkleRoot1"));
      await auditLedger.connect(gateway).anchorMerkleRoot(root, 10);

      const latest = await auditLedger.getLatestRoot();
      expect(latest.root).to.equal(root);
    });

    it("Should prevent non-gateway from anchoring", async function () {
      const root = ethers.keccak256(ethers.toUtf8Bytes("merkleRoot1"));
      await expect(auditLedger.connect(admin).anchorMerkleRoot(root, 10))
        .to.be.revertedWithCustomError(auditLedger, "AccessControlUnauthorizedAccount");
    });

    it("Should prevent anchoring the same root twice", async function () {
      const root = ethers.keccak256(ethers.toUtf8Bytes("merkleRoot1"));
      await auditLedger.connect(gateway).anchorMerkleRoot(root, 10);
      await expect(auditLedger.connect(gateway).anchorMerkleRoot(root, 10))
        .to.be.revertedWith("Root already anchored");
    });
  });

  describe("History", function () {
    it("Should track root history accurately", async function () {
      const root1 = ethers.keccak256(ethers.toUtf8Bytes("root1"));
      const root2 = ethers.keccak256(ethers.toUtf8Bytes("root2"));

      await auditLedger.connect(gateway).anchorMerkleRoot(root1, 5);
      await auditLedger.connect(gateway).anchorMerkleRoot(root2, 15);

      expect(await auditLedger.getRootCount()).to.equal(2);
      
      const entry0 = await auditLedger.getRootAt(0);
      expect(entry0.root).to.equal(root1);
      expect(entry0.logCount).to.equal(5);

      const entry1 = await auditLedger.getRootAt(1);
      expect(entry1.root).to.equal(root2);
      expect(entry1.logCount).to.equal(15);
    });
  });
});
