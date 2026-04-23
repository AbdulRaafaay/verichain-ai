const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  const envPath = path.join(__dirname, "../../../.env.local");
  if (!fs.existsSync(envPath)) {
    throw new Error(".env.local not found. Run deploy script first.");
  }

  const envRaw = fs.readFileSync(envPath, "utf8");
  const envMap = Object.fromEntries(
    envRaw
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const [k, ...rest] = line.split("=");
        return [k, rest.join("=")];
      })
  );

  const accessPolicyAddress = envMap.ACCESS_POLICY_ADDRESS || process.env.ACCESS_POLICY_ADDRESS;
  if (!accessPolicyAddress) {
    throw new Error("ACCESS_POLICY_ADDRESS is missing.");
  }

  const modelPath = path.join(__dirname, "../../ai-engine/model.pkl");
  if (!fs.existsSync(modelPath)) {
    throw new Error("model.pkl not found at packages/ai-engine/model.pkl");
  }

  const modelHashHex = crypto.createHash("sha256").update(fs.readFileSync(modelPath)).digest("hex");
  const modelHashBytes32 = `0x${modelHashHex}`;

  const [signer] = await ethers.getSigners();
  const accessPolicy = await ethers.getContractAt("AccessPolicy", accessPolicyAddress, signer);

  const tx = await accessPolicy.registerModelHash(modelHashBytes32);
  await tx.wait();

  console.log("Model hash registered:", modelHashBytes32);
  console.log("Transaction hash:", tx.hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
