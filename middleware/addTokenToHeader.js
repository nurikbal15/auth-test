// middleware/addTokenToHeader.js

const addTokenToHeader = (req, res, next) => {
    let token = null;
    
    // Pastikan req.cookies telah terdefinisi sebelum mencoba mengakses propertinya
    if (req.cookies && req.cookies.jwtToken) {
      token = req.cookies.jwtToken;
    }
    
    // Jika token ditemukan, tambahkan ke header Authorization
    if (token) {
      req.headers.authorization = `Bearer ${token}`;
    }
    
    next();
  };
  
  module.exports = addTokenToHeader;
  