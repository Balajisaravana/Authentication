const axios = require('axios');
const MOCK_URL = process.env.JSON_MOCK_URL;

// Fetch user data based on userId from mock API
async function getUserByUserId(userId) {
  const res = await axios.get(`${MOCK_URL}/users`);
  return res.data.find(user => user.userId === userId);
}

// Fetch product list from mock API
async function getPayments() {
  const res = await axios.get(`${MOCK_URL}/payments`);
  return res.data;
}

async function getTransactions() {
  const res = await axios.get(`${MOCK_URL}/transactions`);
  return res.data;
}
module.exports = { getUserByUserId, getPayments, getTransactions };
