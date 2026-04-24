const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // deployer = Account #0 — private key 0xac0974... matches GATEWAY_PRIVATE_KEY in .env
  // deployer is given ADMIN_ROLE + GATEWAY_ROLE so the gateway can call all contract functions
  const [deployer, admin1, admin2] = await ethers.getSigners();

  console.log("Deploying contracts with account:", deployer.address);

  // 1. Deploy AccessPolicy
  //    admins[0] = deployer (gets ADMIN_ROLE + DEFAULT_ADMIN_ROLE + GATEWAY_ROLE)
  //    admins[1] = admin1, admins[2] = admin2 (get ADMIN_ROLE for real multi-sig)
  const AccessPolicy = await ethers.getContractFactory("AccessPolicy");
  const accessPolicy = await AccessPolicy.deploy(
    [deployer.address, admin1.address, admin2.address],
    deployer.address
  );
  await accessPolicy.waitForDeployment();
  const accessPolicyAddress = await accessPolicy.getAddress();
  console.log("AccessPolicy deployed to:", accessPolicyAddress);

  // 2. Deploy AuditLedger
  const AuditLedger = await ethers.getContractFactory("AuditLedger");
  const auditLedger = await AuditLedger.deploy(deployer.address);
  await auditLedger.waitForDeployment();
  const auditLedgerAddress = await auditLedger.getAddress();
  console.log("AuditLedger deployed to:", auditLedgerAddress);

  // 3. Save addresses to .env.local
  const envContent = `ACCESS_POLICY_ADDRESS=${accessPolicyAddress}
AUDIT_LEDGER_ADDRESS=${auditLedgerAddress}
GATEWAY_PRIVATE_KEY=${deployer.privateKey}`;
  fs.writeFileSync(path.join(__dirname, "../../../.env.local"), envContent);
  console.log("Contract addresses saved to .env.local");

  // 4. Save deployment summary
  const deploymentInfo = {
    network: "hardhat",
    accessPolicy: accessPolicyAddress,
    auditLedger: auditLedgerAddress,
    gateway: deployer.address,
    admins: [deployer.address, admin1.address, admin2.address],
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(
    path.join(__dirname, "../deployment.json"),
    JSON.stringify(deploymentInfo, null, 2)
  );
  console.log("Deployment complete.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
