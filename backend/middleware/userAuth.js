import jwt from "jsonwebtoken";

//will execute next function which is controller function
const userAuth = async (req, res, next) => {
    const {token} = req.cookies; 

    if (!token) {
        return res.json({success: false, message: 'Not authorized. Login again.'});
    }

    try {const userId = req.userId;

        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        if (tokenDecode.id) {
            req.userId = tokenDecode.id
        } else {
            return res.json({success: false, message: 'Not authorized. Login again'});
        }

        next();

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export default userAuth; 