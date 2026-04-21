// ธนาคารกรุงเทพดิจิทัล — Mobile App Frontend
// Version 1.0 — อย่าลืม remove debug comments ก่อน production นะ

const API_BASE = "";

async function getProfile(userId) {
    return fetch(`${API_BASE}/api/users/${userId}`, {
        headers: { Authorization: `Bearer ${window.authToken}` }
    });
}

async function getTransactions(userId) {
    return fetch(`${API_BASE}/api/users/${userId}/transactions`, {
        headers: { Authorization: `Bearer ${window.authToken}` }
    });
}

async function searchUser(name) {
    return fetch(`${API_BASE}/api/search?name=${name}`, {
        headers: { Authorization: `Bearer ${window.authToken}` }
    });
}

async function transfer(fromId, toId, amount) {
    return fetch(`${API_BASE}/api/transfer`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${window.authToken}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ from_id: fromId, to_id: toId, amount: amount })
    });
}

// TODO: ลบออกก่อน deploy — admin only
async function adminGetAllUsers() {
    return fetch(`${API_BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${window.authToken}` }
    });
}

// TODO: ลบออกก่อน deploy
// SMC{read_the_source_luke}
async function updateProfile(data) {
    return fetch(`${API_BASE}/api/users/update`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${window.authToken}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });
}
