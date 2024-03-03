const crypto = require('crypto');
const fs = require('fs');

class SecurePasswordManager {
    constructor() {
        this.vault = [];
        this.masterKey = null;
        this.isEncrypted = false;
        this.isSynced = false;
    }

    generateMasterKey() {
        this.masterKey = crypto.randomBytes(32).toString('hex');
    }

    encryptPassword(password) {
        if (!this.masterKey) {
            throw new Error("Master key is not set.");
        }
        const cipher = crypto.createCipher('aes-256-ctr', this.masterKey);
        let encryptedPassword = cipher.update(password, 'utf8', 'hex');
        encryptedPassword += cipher.final('hex');
        return encryptedPassword;
    }

    decryptPassword(encryptedPassword) {
        if (!this.masterKey) {
            throw new Error("Master key is not set.");
        }
        const decipher = crypto.createDecipher('aes-256-ctr', this.masterKey);
        let decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8');
        decryptedPassword += decipher.final('utf8');
        return decryptedPassword;
    }

    addCredential(username, password) {
        const encryptedPassword = this.encryptPassword(password);
        this.vault.push({ username, password: encryptedPassword });
    }

    saveVaultToFile(filename) {
        if (!filename) {
            throw new Error("Filename is required.");
        }
        const data = JSON.stringify(this.vault);
        fs.writeFileSync(filename, data);
        console.log(`Vault saved to ${filename}`);
    }

    loadVaultFromFile(filename) {
        if (!filename) {
            throw new Error("Filename is required.");
        }
        const data = fs.readFileSync(filename, 'utf8');
        this.vault = JSON.parse(data);
        console.log(`Vault loaded from ${filename}`);
    }

    syncVault() {
        console.log("Syncing vault across multiple devices...");
        // Simulate syncing process
        setTimeout(() => {
            this.isSynced = true;
            console.log("Vault synced successfully.");
        }, 3000);
    }
}

// 示例用法
const passwordManager = new SecurePasswordManager();
passwordManager.generateMasterKey();
passwordManager.addCredential("user1", "password123");
passwordManager.addCredential("user2", "letmein");
passwordManager.saveVaultToFile("vault.json");
passwordManager.syncVault();
