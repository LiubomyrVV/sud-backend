const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateUser({ name, email, password }) {
    if (!name || !email || !password) return false;
    if (password.length < 6) return false;
    
    // Email validation regex pattern
    if (!emailRegex.test(email)) return false;
    
    return true;
}

module.exports = { validateUser };