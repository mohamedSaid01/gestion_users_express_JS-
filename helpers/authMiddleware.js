import jwt from 'jsonwebtoken';

export const verifyToken = (req, res, next) => {
	let token;

	// 1. Récupération du token selon la source (client ou navigateur)
	if (req.headers.client === 'not-browser') {
		token = req.headers.authorization;
	} else {
		token = req.cookies?.Authorization; // Utilisation de l'opérateur "?" pour éviter une erreur si cookies est undefined
	}

	if (!token) {
		return res.status(403).json({ success: false, message: 'Unauthorized - Token missing' });
	}

	try {
		// 2. Gestion propre du token avec ou sans "Bearer"
		const userToken = token.startsWith('Bearer ')
			? token.split(' ')[1]
			: token;

		// 3. Vérification du token JWT
		const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);

		// 4. Attacher les données vérifiées à req.user
		req.user = jwtVerified;

		// 5. Continuer
		next();
	} catch (error) {
		console.error('JWT verification failed:', error.message);
		return res.status(401).json({ success: false, message: 'Invalid or expired token' });
	}
};
