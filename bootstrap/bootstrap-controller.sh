#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
VAULT_FILE="${REPO_ROOT}/ansible/inventories/main/group_vars/all/vault.yml"
SUDO_GROUP="sudo"
REPO_DEST_NAME="ccdc26"

echo "[*] Installing pipx and Ansible..."
apt-get update
apt-get install -y python3-pip python3-apt
apt-get install -y "${SCRIPT_DIR}/pipx_1.6.0-1_all.deb"
pipx ensurepath --global --force
pipx install --include-deps ansible --global
pipx inject ansible passlib pan-python pan-os-python pywinrm urllib3 --global
pip3 install pan-python pan-os-python pandevice xmltodict --break-system-packages

read -rsp "[?] Enter Ansible vault password: " VAULT_PASS
echo
VAULT_PASS_FILE_ROOT="/root/.vault_pass"
printf '%s' "${VAULT_PASS}" > "${VAULT_PASS_FILE_ROOT}"
chmod 600 "${VAULT_PASS_FILE_ROOT}"

echo "[*] Decrypting vault..."

vault_get() {
    ansible -i localhost, all \
        --connection=local \
        --vault-password-file "${VAULT_PASS_FILE_ROOT}" \
        -e "@${VAULT_FILE}" \
        -m ansible.builtin.debug \
        -a "msg={{ $1 }}" \
        | grep '"msg":' \
        | sed 's/.*"msg": "\(.*\)".*/\1/'
}

AZUL_USER=$(vault_get "vault_new_credentials['ubuntu-wkst'].user")
AZUL_PASS=$(vault_get "vault_new_credentials['ubuntu-wkst'].password")
SSH_PUB_KEY=$(vault_get "vault_ssh_public_key")

# Private key is multiline — extract and unescape \n
SSH_PRIV_KEY=$(ansible -i localhost, all \
    --connection=local \
    --vault-password-file "${VAULT_PASS_FILE_ROOT}" \
    -e "@${VAULT_FILE}" \
    -m ansible.builtin.debug \
    -a "msg={{ vault_ssh_private_key }}" \
    | python3 -c "
import sys, re
output = sys.stdin.read()
m = re.search(r'\"msg\": \"(.*?)\"(?=\s*\})', output, re.DOTALL)
if m:
    print(m.group(1).replace('\\\\n', '\\n'))
")

echo "[*] Azul user will be: ${AZUL_USER}"

echo "[*] Creating user ${AZUL_USER}..."
if ! id "${AZUL_USER}" &>/dev/null; then
    useradd -m -s /bin/bash -G "${SUDO_GROUP}" "${AZUL_USER}"
fi
echo "${AZUL_USER}:${AZUL_PASS}" | chpasswd
usermod -aG "${SUDO_GROUP}" "${AZUL_USER}"

echo "[*] Installing SSH keys for ${AZUL_USER}..."
SSH_DIR="/home/${AZUL_USER}/.ssh"
mkdir -p "${SSH_DIR}"
echo "${SSH_PUB_KEY}" > "${SSH_DIR}/authorized_keys"
printf '%s\n' "${SSH_PRIV_KEY}" > "${SSH_DIR}/ansible_private_key"
chmod 700 "${SSH_DIR}"
chmod 600 "${SSH_DIR}/authorized_keys" "${SSH_DIR}/ansible_private_key"
chown -R "${AZUL_USER}:${AZUL_USER}" "${SSH_DIR}"

REPO_DEST="/home/${AZUL_USER}/${REPO_DEST_NAME}"
echo "[*] Copying repo to ${REPO_DEST}..."
mkdir -p "${REPO_DEST}"
cp -r "${REPO_ROOT}/." "${REPO_DEST}/"
chown -R "${AZUL_USER}:${AZUL_USER}" "${REPO_DEST}"

echo "[*] Installing Ansible galaxy collections for ${AZUL_USER}..."
su - "${AZUL_USER}" -c "ansible-galaxy collection install paloaltonetworks.panos"
su - "${AZUL_USER}" -c "ansible-galaxy collection install community.network"
su - "${AZUL_USER}" -c "ansible-galaxy collection install community.windows"
su - "${AZUL_USER}" -c "ansible-galaxy collection install community.general"
su - "${AZUL_USER}" -c "ansible-galaxy collection install ansible.posix"
su - "${AZUL_USER}" -c "ansible-galaxy collection install randrej.windows"

VAULT_PASS_FILE_AZUL="/home/${AZUL_USER}/.vault_pass"
printf '%s' "${VAULT_PASS}" > "${VAULT_PASS_FILE_AZUL}"
chmod 600 "${VAULT_PASS_FILE_AZUL}"
chown "${AZUL_USER}:${AZUL_USER}" "${VAULT_PASS_FILE_AZUL}"

# Clean up root's vault pass file
rm -f "${VAULT_PASS_FILE_ROOT}"

echo "[*] Locking sysadmin account..."
passwd -l sysadmin

echo ""
echo "[+] Bootstrap complete. Switching to ${AZUL_USER} in ${REPO_DEST}/ansible..."
exec su - "${AZUL_USER}" -c "cd ${REPO_DEST}/ansible && exec bash"
