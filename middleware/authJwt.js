const jwt = require("jsonwebtoken");

exports.verifyToken = (req, res, next) => {
  // Mengambil token dari header Authorization
  let token = req.headers["authorization"];

  if (!token) return res.status(403).send({ message: "No token provided!" });

  // Jika token diawali dengan 'Bearer', ambil bagian setelah 'Bearer'
  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length); // Mengambil token setelah "Bearer "
  }

  // Verifikasi token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized!" });
    req.userId = decoded.id;
    next();
  });
};
