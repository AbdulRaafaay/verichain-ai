const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer, admin1, admin2, admin3, gateway] = await ethers.getSigners();

  console.log("Deploying contracts with the account:", deployer.address);

  // 1. Deploy AccessPolicy
  const AccessPolicy = await ethers.getContractFactory("AccessPolicy");
  const accessPolicy = await AccessPolicy.deploy(
    [admin1.address, admin2.address, admin3.address],
    gateway.address
  );
  await accessPolicy.waitForDeployment();
  const accessPolicyAddress = await accessPolicy.getAddress();
  console.log("AccessPolicy deployed to:", accessPolicyAddress);

  // 2. Deploy AuditLedger
  const AuditLedger = await ethers.getContractFactory("AuditLedger");
  const auditLedger = await AuditLedger.deploy(gateway.address);
  await auditLedger.waitForDeployment();
  const auditLedgerAddress = await auditLedger.getAddress();
  console.log("AuditLedger deployed to:", auditLedgerAddress);

  // 3. Save addresses to .env.local for development use
  const envContent = `
ACCESS_POLICY_ADDRESS=${accessPolicyAddress}
AUDIT_LEDGER_ADDRESS=${auditLedgerAddress}
GATEWAY_PRIVATE_KEY=${gateway.privateKey}
`;
  const envPath = path.join(__dirname, "../../../.env.local");
  fs.writeFileSync(envPath, envContent.trim());
  console.log("Contract addresses saved to .env.local");

  // Also save a JSON for reference
  const deploymentInfo = {
    network: "hardhat",
    accessPolicy: accessPolicyAddress,
    auditLedger: auditLedgerAddress,
    gateway: gateway.address,
    admins: [admin1.address, admin2.address, admin3.address],
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(
    path.join(__dirname, "../deployment.json"),
    JSON.stringify(deploymentInfo, null, 2)
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
