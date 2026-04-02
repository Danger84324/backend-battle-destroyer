// scripts/ensureAdmin.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    isPro: { type: Boolean, default: false },
    credits: { type: Number, default: 0 }
});

const User = mongoose.model('User', UserSchema);

async function ensureAdminUser() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to MongoDB');
        
        // Check if admin exists
        const adminExists = await User.findOne({ isAdmin: true });
        
        if (!adminExists) {
            console.log('No admin user found. Creating one...');
            
            const hashedPassword = await bcrypt.hash('Admin@123456', 10);
            
            const adminUser = new User({
                username: 'superadmin',
                email: 'admin@battle-destroyer.com',
                password: hashedPassword,
                isAdmin: true,
                isPro: true,
                credits: 999999
            });
            
            await adminUser.save();
            console.log('✅ Admin user created successfully!');
            console.log('📝 Admin credentials:');
            console.log('   Username: superadmin');
            console.log('   Email: admin@battle-destroyer.com');
            console.log('   Password: Admin@123456');
            console.log('⚠️  Please change the password after first login!');
        } else {
            console.log(`✅ Admin user already exists: ${adminExists.username} (${adminExists._id})`);
            console.log('   Use this ID for DEFAULT_ADMIN_ID in .env:');
            console.log(`   DEFAULT_ADMIN_ID=${adminExists._id}`);
        }
        
        process.exit(0);
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
}

ensureAdminUser();