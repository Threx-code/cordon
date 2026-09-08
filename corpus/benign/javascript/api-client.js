// Ordinary front-end data access: network egress and env reads, no execution.
const BASE = process.env.API_BASE_URL || "https://api.example.com";

export async function getUser(id) {
  const response = await fetch(`${BASE}/users/${id}`, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  return response.json();
}

export async function updateUser(id, patch) {
  const response = await fetch(`${BASE}/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return response.json();
}
