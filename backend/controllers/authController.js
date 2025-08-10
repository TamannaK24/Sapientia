import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';  
import userModel from '../models/userModel.js'
import transporter from '../config/nodemailer.js'

//REGISTER
export const register = async (req, res)=> {
    //puls userinput from post request body 
    const {name, email, password} = req.body; 

    //if anything is missing send failure 
    if(!name || !email || !password) {
        return res.json({success: false, message: 'Missing Details'}) 
    }

    try {
        //checks existing user
        const existingUser = await userModel.findOne({email})

        if (existingUser) {
            return res.json({success: false, message: "User already exists"})
        }

        //hashes password and creates new userModel in mongodb 
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password: hashedPassword});
        await user.save();
        
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'}); 
        res.cookie('token', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 //in seconds
        }) 

        //sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Sapientia',
            text: `Welcome to Sapientia. Your account has been created with email id: ${email}`

        }

        await transporter.sendMail(mailOptions)

        return res.json({success: true}); 

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

//LOGIN
export const login = async (req, res) => {
    const {email, password} = req.body; 
    //checks email and password
    if (!email || !password) {
        return res.json({success: false, message: 'Email and password are required'})
    }

    try {
        //tries to find user with email, if no matching user with email exists it throws error
        const user = await userModel.findOne({email});
        if (!user) {
            return res.json({success: false, message: 'Invalid email'})
        }

        //checks if passwords match if not, throws error
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.json({success: false, message: 'Invalid password'})
        }

        // if user exists cookie is created to hold token 
        //jwt token created and user id is encoded in the token and signed with secret key only the server knows
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'}); 
        res.cookie('token', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 //in seconds
        });

        return res.json({success: true}); 

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

//LOGOUT
export const logout = async (req, res) => {
    //removing token using clear cookie
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: "Logged Out"})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
} 


//Send Verification OTP to user's email 
export const sendVerifyOtp = async (req, res) => {
    try {
        const {userId} = req.body; 

        const user = await userModel.findById(userId); 

        if (user.isAccountVerified) {
            return res.json({success: false,
                message: "Account already verified"
            }) 
        }

        const otp = String(Math.floor(100000 + Math.random() * 9000000)) 

        user.verifyOtp = otp; 
        //expirey date is 1 day from now
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save(); 

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account with OTP.`
        }

        await transporter.sendMail(mailOptions)

    } catch (error) {
        res.json({ success: false, message: error.message }); 
    }
}

//verify email using otp
export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body; 

    if (!userId || !otp) {
        return res.json({success: false, message: 'Missing Details'});
    }
    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({success: false, message: 'User not found'});
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyOtpExpireAt < Date.now) {
            return res.json({success: false, message: 'OTP Expired'});
        }

        user.isAccountVerified = true; 
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save()
        return res.json({success: false, message: 'Email verified successfully'});

    } catch (error) {
        return res.json({success: false, message: 'Missing Details'});
    }
}

//Checks if user is authenticated
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true }); 
    } catch (error) {
        res.json({ success: false, message: error.message}); 
    }
}

//send password reset otp
export const sendResetOtp = async (req, res) => {
    const {email} = req.body; 

    if (!email) {
        return res.json({success: false, message: "Email is required."}); 
    }
     
    try {
        const user = await userModel.findOne({email}); 
        if (!user) {
            return res.json({success: false, message: "User not found."}); 
        }

        const otp = String(Math.floor(100000 + Math.random() * 9000000)) 

        user.resetOtp = otp; 
        //expirey date is few min from now
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000
 
        await user.save(); 

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP for resetting your password is ${otp}. Verify your account with OTP.`
        };

        await transporter.sendMail(mailOptions);

        return res.json({success:true, message: 'OTP sent to your email.'})


    } catch (error) {
        res.json({ success: false, message: error.message}); 
    }
}

//reset user password
export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body; 

    if (!email || !otp || !newPassword) {
        return res.json({success: false, message: 'Email, OTP, and new password are required.'})
    }

    try {
        const user = await userModel.findOne({email});
        if (!user) {
            res.json({ success: false, message: 'User not found.'}); 
        }

        if(user.resetOtp === "" || user.resetOtp !== otp) {
            res.json({ success: false, message: 'Invalid OTP'}); 
        }

        if (user.resetOtpExpireAt < Date.now) {
            res.json({ success: false, message: 'OTP Expired'}); 
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = hashedPassword; 
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save(); 

        return res.json({ success: true, message: 'Password has been reset successfully'}); 

    } catch (error) {
        res.json({ success: false, message: error.message}); 
    }
}