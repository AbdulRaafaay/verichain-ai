const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AccessPolicy", function () {
  let AccessPolicy;
  let accessPolicy;
  let owner, admin1, admin2, admin3, gateway, user1;
  let userHash, resourceHash;

  beforeEach(async function () {
    [owner, admin1, admin2, admin3, gateway, user1] = await ethers.getSigners();

    AccessPolicy = await ethers.getContractFactory("AccessPolicy");
    accessPolicy = await AccessPolicy.deploy([admin1.address, admin2.address, admin3.address], gateway.address);

    userHash = ethers.keccak256(ethers.toUtf8Bytes("user123"));
    resourceHash = ethers.keccak256(ethers.toUtf8Bytes("resource456"));
  });

  describe("Deployment", function () {
    it("Should set the correct roles", async function () {
      const ADMIN_ROLE = await accessPolicy.ADMIN_ROLE();
      const GATEWAY_ROLE = await accessPolicy.GATEWAY_ROLE();

      expect(await accessPolicy.hasRole(ADMIN_ROLE, admin1.address)).to.be.true;
      expect(await accessPolicy.hasRole(ADMIN_ROLE, admin2.address)).to.be.true;
      expect(await accessPolicy.hasRole(ADMIN_ROLE, admin3.address)).to.be.true;
      expect(await accessPolicy.hasRole(GATEWAY_ROLE, gateway.address)).to.be.true;
    });
  });

  describe("Access Control", function () {
    it("Should deny access by default", async function () {
      expect(await accessPolicy.connect(gateway).checkAccess.staticCall(userHash, resourceHash)).to.be.false;
    });

    it("Should allow access after multi-sig approval", async function () {
      const changeHash = ethers.keccak256(ethers.toUtf8Bytes("change1"));

      await accessPolicy.connect(admin1).proposeChange(changeHash);
      await accessPolicy.connect(admin1).approveChange(changeHash, userHash, resourceHash, true);
      await accessPolicy.connect(admin2).approveChange(changeHash, userHash, resourceHash, true);

      expect(await accessPolicy.connect(gateway).checkAccess.staticCall(userHash, resourceHash)).to.be.true;
    });

    it("Should not execute change with only one approval", async function () {
      const changeHash = ethers.keccak256(ethers.toUtf8Bytes("change-threshold"));
      await accessPolicy.connect(admin1).proposeChange(changeHash);
      await accessPolicy.connect(admin1).approveChange(changeHash, userHash, resourceHash, true);

      expect(await accessPolicy.connect(gateway).checkAccess.staticCall(userHash, resourceHash)).to.be.false;
    });

    it("Should prevent duplicate approvals", async function () {
        const changeHash = ethers.keccak256(ethers.toUtf8Bytes("change1"));
        await accessPolicy.connect(admin1).proposeChange(changeHash);
        await accessPolicy.connect(admin2).approveChange(changeHash, userHash, resourceHash, true);
        
        await expect(accessPolicy.connect(admin2).approveChange(changeHash, userHash, resourceHash, true))
            .to.be.revertedWith("Already approved");
    });
  });

  describe("Session Management", function () {
    it("Should create and revoke sessions", async function () {
      const sessionId = ethers.keccak256(ethers.toUtf8Bytes("session1"));

      await accessPolicy.connect(gateway).createSession(sessionId, userHash);
      let session = await accessPolicy.getSession(sessionId);
      expect(session.active).to.be.true;

      await accessPolicy.connect(gateway).revokeSession(sessionId, "Risk score high");
      session = await accessPolicy.getSession(sessionId);
      expect(session.active).to.be.false;
    });

    it("Should prevent duplicate sessions", async function () {
      const sessionId = ethers.keccak256(ethers.toUtf8Bytes("session1"));
      await accessPolicy.connect(gateway).createSession(sessionId, userHash);
      await expect(accessPolicy.connect(gateway).createSession(sessionId, userHash))
        .to.be.revertedWith("Session already exists");
    });
  });

  describe("Security Guardrails", function () {
    it("Should only allow Gateway to check access", async function () {
      const GATEWAY_ROLE = await accessPolicy.GATEWAY_ROLE();
      await expect(accessPolicy.connect(user1).checkAccess(userHash, resourceHash))
        .to.be.revertedWithCustomError(accessPolicy, "AccessControlUnauthorizedAccount")
        .withArgs(user1.address, GATEWAY_ROLE);
    });

    it("Should support emergency pause", async function () {
      await accessPolicy.connect(admin1).emergencyPause();
      await expect(accessPolicy.connect(gateway).checkAccess(userHash, resourceHash))
        .to.be.revertedWithCustomError(accessPolicy, "EnforcedPause");

      await accessPolicy.connect(admin1).emergencyUnpause();
      await expect(accessPolicy.connect(gateway).checkAccess(userHash, resourceHash))
        .to.not.be.reverted;
    });
  });
});
